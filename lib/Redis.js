const Redis = require('ioredis');

// Use the entire URI from the environment variable (which ioredis handles gracefully)
const connectionString = process.env.REDIS_URL || process.env.REDISCLOUD_URL || 'redis://localhost:6379';

const redis = new Redis(connectionString); 

redis.on('error', (err) => {
  // Use a more specific log level for production
  console.error('CRITICAL: Redis connection error. Data persistence is compromised.', err);
});

module.exports = redis;