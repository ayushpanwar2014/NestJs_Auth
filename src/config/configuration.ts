export default () => ({
    port: parseInt(process.env.PORT || '4000', 10),
    mongoUri: process.env.MONGO_URI,
    jwtSecret: process.env.JWT_SECRET,
    frontendUrl: process.env.FRONTEND_URL,
});
