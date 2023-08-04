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
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const cors = require('cors');


const User = require("./models/user");
const Post = require("./models/post");
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
      "img-src": ["'self'", "https: data:"]
    },
  })
)

app.use(cors());
app.use(passport.initialize());
app.use(limiter);
app.use(compression());
app.use(logger('dev'));
app.use(express.json({limit: '50mb'}));
app.use(express.urlencoded({ extended: false, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


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
  async(jwt_payload, done) => {
    try {
    const user = await User.findOne({_id: jwt_payload.user._id}).exec();
    if (!user) {
      return done(null, false, {message: "Token not authorized"});
    } 
    if (user) {
        return done(null, user);
    } 
    else {
        return done(null, false);
    }

    }
    catch(err) {
      return done(err)
    }
  }));

app.get('/posts', asyncHandler(async(req, res, next) => {
  const posts = await Post.find().sort({ createdAt: -1 }).populate('author').exec();
  res.json(posts);
}))

app.get('/posts/:postid', asyncHandler(async(req, res, next) => {
  const post = await Post.findById(req.params.postid).populate('author').exec();

  if (post === null) {
   return res.status(404).json({message: 'Post not found', status: 404})
}

  res.json(post)
}));

app.get('/posts/:userid', asyncHandler(async(req, res, next) => {
  const posts = await Post.find({ author: req.params.userid}).populate('author').sort({date: -1}).exec();

  if (posts === null) {
    return res.status(404).json({message: 'Posts not found', status: 404})
 }

  res.json(posts)
}))

app.get('/posts/:postid/comments', asyncHandler(async(req, res, next) => {
  const comments = await Comment.find({ post: req.params.postid }).populate('name').sort({date: -1}).exec();

  res.json(comments);
}))

app.get('/posts/:postid/comments/:commentid', asyncHandler(async(req, res, next) => {
  const comment = await Comment.findById(req.params.commentid).exec();

  res.json(comment);
}))

app.post('/posts/:postid/comments', upload.any(), passport.authenticate('jwt', {session: false}), [
  body("content")
  .trim()
  .isLength({ min: 1 })
  .escape()
  .withMessage("Comment must have text"),

  asyncHandler(async(req, res, next) => {
    const errors = validationResult(req);

  let userid;

  if (typeof window !== 'undefined') {
  let jwt = localStorage.getItem('jwt');
  let jwtdecoded = jwt_decode(jwt);
  userid = jwtdecoded._id;
  } else {
    userid = "64a674096e0c76ad9feb1d98"
  }

    const comment = new Comment({
      name: userid,
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


app.post('/signup', upload.any(), [
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
  })
  .withMessage('Passwords must match'),
  asyncHandler(async(req, res, next) => {

    const errors = validationResult(req);

    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    if (!errors.isEmpty()) {
      return res.json({
        user: user,
        errors: errors.array(),
      });
    } else {
      let salt = bcrypt.genSaltSync(10);
      let hash = bcrypt.hashSync(req.body.password, salt);
      user.password = hash;
      await user.save();
      res.json(user);
    }
  })
])


app.post("/login", async(req, res, next) => {
  passport.authenticate(
    'local', {session: false}, async(err, user, info) => {
      if (!user || err) {
        return res.status(404).json({message: "Incorrect username or password", status: 404})
      } else {
        const opts = {};
        opts.expiresIn = 3600;
        const secret = process.env.SECRET;
        const authuser = await User.findOne({ username: req.body.username }).exec();

            const body = { _id: authuser._id, username: authuser.username };
            const token = jwt.sign({ user: body }, secret, opts);
            if (typeof window !== 'undefined') {
            localStorage.setItem("jwt", JSON.stringify(token));
            }
            return res.json({ token });
      }
    }
  ) (req, res, next)}
);

app.post("/posts", upload.single('cover_image'), passport.authenticate('jwt', {session: false}), [
  body("title", "Title must not be empty")
  .trim()
  .isLength({min: 1})
  .escape(),
  body("content", "Content must not be empty")
  .trim()
  .isLength({min: 1})
  .escape(),
  body("cover_image", "Cover image required")
  .custom((value, {req}) => {
    if (!req.file) throw new Error('Cover image is required');
    return true;
  }),

asyncHandler(async(req, res, next) => {

  const errors = validationResult(req);

  const post = new Post({
    title: req.body.title,
    content: req.body.content, 
    author: req.body.author,
    cover_image: req.file.buffer,
    published: req.body.published,
  });

  if (!errors.isEmpty()) {
    return res.json({
      post: post,
      errors: errors.array(),
    });
  } else {
    await post.save();
    res.json(post);
  }

})]);

app.put("/posts/:postid", upload.any(), passport.authenticate('jwt',  {session: false}), [
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

    let userid;
    
    if (typeof window !== 'undefined') {
      let jwt = localStorage.getItem('jwt');
      let jwtdecoded = jwt_decode(jwt);
      userid = jwtdecoded._id;
      } else {
        userid = "64a674096e0c76ad9feb1d98"
      };

      let selectpost = await Post.findById(req.params.postid).exec();

      if (selectpost.author === userid) {
    
    

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
  } else {
    res.status(401).json({message: 'Unauthorized to edit', status: 401})
  }

  })
]);

app.put('/posts/:postid/comments/:commentid', upload.any(), passport.authenticate('jwt', {session: false}), [
  body("content")
  .trim()
  .isLength({ min: 1 })
  .escape()
  .withMessage("Comment must have text"),

  asyncHandler(async(req, res, next) => {
    const errors = validationResult(req);

    let userid;

    if (typeof window !== 'undefined') {
      let jwt = localStorage.getItem('jwt');
      let jwtdecoded = jwt_decode(jwt);
      userid = jwtdecoded._id;
      } else {
        userid = "64a674096e0c76ad9feb1d98"
      }
    
    let selectcomment = await Comment.findById(req.params.commentid).exec();

    if (selectcomment.name === userid) {
    

    const comment = new Comment({
      name: userid,
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
  } else {
    res.status(401).json({message: 'Unauthorized to edit', status: 401})
  }

})])

app.delete("/posts/:postid", passport.authenticate('jwt', {session: false}), asyncHandler(async(req, res, next) => {
  let deletePost = Post.findById(req.params.postid).exec();
  let userid;

  if (typeof window !== 'undefined') {
    let jwt = localStorage.getItem('jwt');
    let jwtdecoded = jwt_decode(jwt);
    userid = jwtdecoded._id;
    } else {
      userid = "64a674096e0c76ad9feb1d98"
    }

    if (deletePost.author === userid) {
      await Comment.deleteMany({post: req.params.postid}).exec();
      await Post.findByIdAndRemove(req.params.postid).exec();
      res.json('deleted')
    } else {
      res.status(401).json({message: 'Unauthorized to delete', status: 401})
    }

}))


app.delete("/posts/:postid/comments/:commentid", passport.authenticate('jwt', {session: false}), asyncHandler(async(req, res, next) => {
  let deleteComment = Comment.findById(req.params.commentid).exec();

  let userid;

  if (typeof window !== 'undefined') {
    let jwt = localStorage.getItem('jwt');
    let jwtdecoded = jwt_decode(jwt);
    userid = jwtdecoded._id;
    } else {
      userid = "64a674096e0c76ad9feb1d98"
    }
  
  if (deleteComment.name === userid) {
    await Comment.findByIdAndRemove(req.params.commentid).exec();
    res.json();
    } else {
      res.status(401).json({message: 'Unauthorized to delete', status: 401})
    }
}))



module.exports = app;
