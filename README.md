# Blog-API

## About This Project

This is the backend API for the blogging website that can be found <a href="https://cerulean-seahorse-473a4d.netlify.app/" target="break">here</a> 
and the code-base for the front end <a href="https://github.com/mulcharv/blogfrontend">here</a>.

This project has the following routes and features:

* Passport JS strategies to sign up as a user and authenticate a JWT.
* GET all posts.
* GET a post by post ID.
* GET all posts by a user ID.
* GET all comments by a post ID.
* GET a specific comment by a post and comment ID.
* POST a comment under a post via its ID.
* POST username, password, and password confirmation to sign up.
* POST username and password to login.
* POST a blog post with title, content, author (user ID), and publish status.
* PUT new post information by post ID.
* PUT new comment information by post and comment ID.
* DELETE post by post ID.
* DELETE comment by post and comment ID.
* Have all PUT, POST, and DELETE routes above authenticated by the JWT passport strategy.

This project uses the Node.js web framework Express to build out the API and its routes. 
It also uses Mongoose to build out data models for comment, post, and user schemas. 

## Key Learning 

This project was my first experience with such a high level of routes, authentication, and handling of data, which allowed me to learn how to do the following:

* Set up and connect Mongo DB database via Mongoose to Express API.
* Utilize Multer to handle multi-form part data on POST and PUT requests.
* Structuring API route paths as per REST protocols to ensure seperation of concerns and no route conflicts.
* Logicial error handling with and without express-validator.
* Constructing and saving new instances of schemas based on data delivered within the body of fetch requests.
* Writing the correct commands and options to update and deliver existing schema instances in res.json format.
* Building schema models that are efficient in how they relate to eachother and what extra information they can communicate.
  For this project that meant having posts and comments use the user as the base reference. It also required setting timestamps to true,
  creating virtual properties for formatted timestamps, and setting toObject and toJSON of those virtuals to true.
* Including additional levels of authorization such as checking the user ID from the JWT matches the user ID of the post they are trying to delete.

## Future Opportunities 

After completion, there are several features I realized would enhance the application which I look to come back in the future and include: 

* Expanding on the user model schema to include more details (country, avatar image, favourite music genres/musicians) that would provide enough
  to create user bio pages for public viewing by all site users.
* The ability for logged in users to like certain posts, comments, and friends, which would yield data that could be included on their front end profile page
  (favourited comments, posts, and users).
* Including cover images as part of the post schema so that each post on the front-end could have a corresponding photo at the top of it.

## Acknowledgements 

Resources that were helpful in creating this application.

* <a href="https://www.npmjs.com/package/multer" target="blank">Multer</a>
* <a href="https://www.npmjs.com/package/jwt-decode" target="blank">JWT Decode</a>
* <a href="https://www.npmjs.com/package/dotenv" target="blank">Dotenv</a>
* <a href="https://www.npmjs.com/package/luxon" target="blank">Luxon</a>
* <a href="https://www.passportjs.org/" target="blank">PassportJs</a>
* <a href="https://www.npmjs.com/package/bcryptjs" target="blank">BcyrptJs</a>

## About Me 

Visit my <a href="https://github.com/mulcharv" target="blank">about me</a> page to learn what I'm up to and contact me. 
