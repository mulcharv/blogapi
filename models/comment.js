const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const { DateTime } = require("luxon");

const CommentSchema = new Schema({
    name: { type: Schema.Types.ObjectId, ref: "User", required: true },
    content: { type: String, required: true}, 
    post: { type: Schema.Types.ObjectId, ref: "Post", required: true},
}, {timestamps: true, toObject: {virtuals: true}, toJSON: {virtuals: true} });

CommentSchema.virtual("timestamp_formatted").get(function () {
    return DateTime.fromJSDate(this.createdAt).toLocaleString(DateTime.DATE_MED);
});

module.exports = mongoose.model("Comment", CommentSchema);