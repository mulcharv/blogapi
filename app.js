const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const asyncHandler = require("express-async-handler");
const { body, validationResult, customSanitizer } = require("express-validator"); 
const passportJWT = require('passport-jwt');
const jwt = require("jsonwebtoken");
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcryptjs');
const jwt_decode = require("jwt-decode");
const mongoose = require("mongoose");
mongoose.set("strictQuery", false);
require('dotenv').config();
const dev_db_url = process.env.MONGOURL;
const mongoDB = process.env.MONGODB_URI || dev_db_url;
const compression = require("compression");
const helmet = require("helmet");
const RateLimit = require("express-rate-limit");

const User = require("./models/user");
const Post = require("./models/message");
const Comment = require("./models/comment");
const { session } = require('passport');


mongoose.connect(mongoDB, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const app = express();

const limiter = RateLimit({
  windowMs: 1*60*1000,
  max: 20,
})

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      "script-src": ["'self'", "code.jquery.com", "cdn.jsdelivr.net"],
    },
  })
)

app.use(limiter);
app.use(compression());
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});


passport.use(new LocalStrategy(
  async(username, password, done) => {
    try {
      const user = await User.findOne({ username: username }).exec();
      if (!user) {
        return done(null, false, { message: "Incorrect username"});
      } else {
        bcrypt.compare(password, user.password, (err, res) => {
          if (res === true) {
            return done(null, user)
          } else {
            return done(null, false, { message: "Incorrect password"})
          }
        })
      }
    }
    catch(err) {
      return done(err)
    }
  }));


  passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET,
  },
  (jwt_payload, done) => {
    User.findOne({_id: jwt_payload._id}, function(err, user) {
      if (err) {
        return done(err, false)
      }
      
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    });
  }));

app.get('/', asyncHandler(async(req, res, next) => {
  const posts = await Post.find().sort({ createdAt: -1 }).populate('author').exec();
  res.json(posts);
}))

app.get('posts/:postid', asyncHandler(async(req, res, next) => {
  const post = await Post.findById(req.params.postid).populate('author').exec();

  if (post === null) {
    const err = new Error("Post not found");
    err.status = 404;
    return next(err);
}

  res.json(post)
}));

app.get('posts/:postid/comments', asyncHandler(async(req, res, next) => {
  const comments = await Comment.find({ post: req.params.postid }, "name comment").exec();

  res.json(comments);
}))

app.post('posts/:postid/comments', [
  body("name")
  .trim()
  .isLength({ min: 1 })
  .escape()
  .withMessage("Name must be specified"),
  body("content")
  .trim()
  .isLength({ min: 1 })
  .escape()
  .withMessage("Comment must have text"),

  asyncHandler(async(req, res, next) => {
    const errors = validationResult(req);

    const comment = new Comment({
      name: req.body.name,
      content: req.body.content,
      post: req.params.postid,
    });
    if (!errors.isEmpty()) {

      res.json({
          comment: comment,
          errors: errors.array(),
      });
      return; 
  } else {
      await comment.save();
      res.json(comment)
  }
  })
]);


app.post('/signup', [
  body("username", 'Username must not be empty')
  .trim()
  .isLength({ min: 1 })
  .escape(),
  body("password", "Password must not be empty")
  .trim()
  .isLength({ min: 1 })
  .escape(),
  body('passwordConfirmation').custom((value, { req }) => {
    return value === req.body.password;
  }),
  asyncHandler(async(req, res, next) => {

    const errors = validationResult(req);

    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    if (!errors.isEmpty()) {
      res.json({
        user: user,
        errors: errors.array(),
      });
      return;
    } else {
      let salt = bcrypt.genSaltSync(10);
      let hash = bcrypt.hashSync(req.body.password, salt);
      user.password = hash;
      await user.save();
      res.json(user);
    }
  })
])


app.post("/login", 
  passport.authenticate(
    'local',
    { session: false, failureRedirect: '/login', failureMessage: true},
  ),
  async(req, res, next) => {
        const opts = {};
        opts.expiresIn = 3600;
        const secret = process.env.SECRET;
        const authuser = await User.findOne({ username: req.body.username }).exec();

            const body = { _id: authuser._id, username: authuser.username };
            const token = jwt.sign({ user: body }, secret, opts);
            localStorage.setItem("jwt", JSON.stringify(token));
            return res.json({ token });
          }
);

app.post("/posts", passport.authenticate('jwt', {session: false}), [
  body("title", "Title must not be empty")
  .trim()
  .isLength({min: 1})
  .escape(),
  body("content", "Content must not be empty")
  .trim()
  .isLength({min: 1})
  .escape(),

asyncHandler(async(req, res, next) => {

  const errors = validationResult(req);

  let jwt = localStorage.getItem('jwt');
  let jwtdecoded = jwt_decode(jwt);
  let userid = jwtdecoded._id;

  const post = new Post({
    title: req.body.title,
    content: req.body.content, 
    author: userid,
    published: req.body.published,
  });

  if (!errors.isEmpty()) {
    res.json({
      post: post,
      errors: errors.array(),
    });
    return;
  } else {
    await post.save();
    res.json(post);
  }

})]);

app.put("/posts/:postid", passport.authenticate('jwt',  {session: false}), [
  body("title", "Title must not be empty")
  .trim()
  .isLength({min: 1})
  .escape(),
  body("content", "Content must not be empty")
  .trim()
  .isLength({min: 1})
  .escape(),

  asyncHandler(async(req, res, next) => {
    const errors = validationResult(req);

    let jwt = localStorage.getItem('jwt');
    let jwtdecoded = jwt_decode(jwt);
    let userid = jwtdecoded._id;

    const post = new Post({
      title: req.body.title,
      content: req.body.content,
      author: userid,
      published: req.body.published,
      _id: req.params.postid,
    });

    if (!errors.isEmpty()) {
      res.json({
        post: post,
        errors: errors.array(),
      });
      return;
    } else {
      const thepost = await Post.findByIdAndUpdate(req.params.postid, post, {});

      res.json(thepost);
    }

  })
]);

app.put('posts/:postid/comments/:commentid', passport.authenticate('jwt', {session: false}), [
  body("name")
  .trim()
  .isLength({ min: 1 })
  .escape()
  .withMessage("Name must be specified"),
  body("content")
  .trim()
  .isLength({ min: 1 })
  .escape()
  .withMessage("Comment must have text"),

  asyncHandler(async(req, res, next) => {
    const errors = validationResult(req);

    const comment = new Comment({
      name: req.body.name,
      content: req.body.content,
      post: req.params.postid,
      _id: req.params.commentid
    });

    if (!errors.isEmpty()) {
      res.json({
        comment: comment,
        errors: errors.array(),
      });
      return;
    } else {
      const thecomment = await Comment.findByIdAndUpdate(req.params.commentid, comment, {});

      res.json(thecomment);
    }

})])


app.delete("/posts/:postid/comments/:commentid", passport.authenticate('jwt', {session: false}), asyncHandler(async(req, res, next) => {
  await Post.findByIdAndRemove(req.params.commentid).exec();
}))


module.exports = app;
