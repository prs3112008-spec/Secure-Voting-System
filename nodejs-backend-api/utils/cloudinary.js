const cloudinary = require('cloudinary').v2;

function configureCloudinary() {
    cloudinary.config({
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET,
        secure: true
    });
}

configureCloudinary();

function isCloudinaryConfigured() {
    return ['CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET']
        .every(name => typeof process.env[name] === 'string' && process.env[name].trim() !== '');
}

async function uploadCandidatePhoto(photoUrl) {
    if (photoUrl.startsWith('https://') || photoUrl.startsWith('http://')) {
        return photoUrl;
    }

    if (!photoUrl.startsWith('data:image/') || !isCloudinaryConfigured()) {
        return photoUrl;
    }

    configureCloudinary();

    const result = await cloudinary.uploader.upload(photoUrl, {
        folder: 'secure-voting/candidates',
        resource_type: 'image',
        transformation: [{
            width: 400,
            height: 400,
            crop: 'fill',
            gravity: 'face',
            quality: 'auto',
            fetch_format: 'auto'
        }]
    });
    return result.secure_url;
}

module.exports = { isCloudinaryConfigured, uploadCandidatePhoto };
