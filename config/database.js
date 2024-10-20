// server/sequelize.js
const { Sequelize } = require('sequelize');

// Create a Sequelize instance
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: 'localhost',
    dialect: 'mysql', // Change to 'postgres' if you use PostgreSQL
});

// Test the connection
const connectDB = async () => {
    try {
        await sequelize.authenticate();
        console.log('Connection to the database has been established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
};

connectDB();

module.exports = sequelize;
