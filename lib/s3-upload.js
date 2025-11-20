const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

const s3 = new S3Client({
    region : process.env.AWS_REGION,
  
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

const deleteFromS3 = async (fileUrl) => {

    if(!fileUrl.includes(process.env.AWS_BUCKET_NAME)) {
        console.log('Trying to delete from other bucket')
        return 
    }
    
    try {
        const parsedLink = new URL(fileUrl)
        const Key = parsedLink.pathname.substring(1)

        const deleteParams = {
            Bucket : process.env.AWS_BUCKET_NAME,
            Key : Key
        }

        await s3.send(new DeleteObjectCommand(deleteParams))
        console.log(`[S3 DELETE SUCCESS]: Deleted object with Key: ${Key}`);
    }
    catch (err) {
        console.log(err)
    }


}


module.exports = {uploadToS3, deleteFromS3}