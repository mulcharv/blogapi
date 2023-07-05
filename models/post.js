const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const { DateTime } = require("luxon");

const PostSchema = new Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: Schema.Types.ObjectId, ref: "User", required: true},
    published: { type: Boolean, required: true }, 
}, {timestamps: true });

PostSchema.virtual("timestamp_formatted").get(function () {
    return DateTime.fromJSDate(this.createdAt).toLocaleString(DateTime.DATE_MED);
});

PostSchema.virtual("url").get(function () {
    return `/posts/${this._id}`;
})

module.exports = mongoose.model("Post", PostSchema);