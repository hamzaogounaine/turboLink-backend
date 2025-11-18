const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const s3 = new S3Client({
    region : process.env.AWS_REGION,
    credentials : {
        accessKeyId : process.env.AWS_ACCESS_KEY,
        secretAccessKey : process.env.AWS_SECRET_KEY
    }
})

const uploadToS3 = async (fileBuffer , fileName , mimeType ) => {
    const uploadParams = {
        Bucket : process.env.AWS_BUCKET_NAME,
        Key : fileName,
        Body : fileBuffer,
        ContentType : mimeType
    }

    await s3.send(new PutObjectCommand(uploadParams))
    return `https://${process.env.AWS_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileName}`;
}


module.exports = {uploadToS3}