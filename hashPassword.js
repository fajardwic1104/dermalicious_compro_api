const bcrypt = require('bcrypt');

const hashPassword = async (password) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log(`Hashed Password: ${hashedPassword}`);
    } catch (err) {
        console.error('Error hashing password:', err);
    }
};

// Replace 'your_password' with the password you want to hash
hashPassword('#He123llo');
