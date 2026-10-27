const fs = require("fs");
const path = require("path");

function readUpload(fileName) {
  return fs.readFileSync(path.join("/srv/uploads", fileName));
}

function readAvatar(avatarName) {
  return fs.readFileSync(path.join("/srv/avatars", path.basename(avatarName)));
}

module.exports = { readUpload, readAvatar };
