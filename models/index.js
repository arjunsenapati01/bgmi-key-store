const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: 'keys.db',
    logging: false
});

const User = sequelize.define('User', {
    username: {
        type: DataTypes.STRING(80),
        unique: true,
        allowNull: false
    },
    password: {
        type: DataTypes.STRING(120),
        allowNull: false
    },
    isAdmin: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    }
});

const SerialKey = sequelize.define('SerialKey', {
    key: {
        type: DataTypes.STRING(50),
        unique: true,
        allowNull: false
    },
    isUsed: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    price: {
        type: DataTypes.FLOAT,
        allowNull: false
    },
    category: {
        type: DataTypes.STRING(20),
        allowNull: false
    },
    duration: {
        type: DataTypes.STRING(10),
        allowNull: false
    }
});

const Purchase = sequelize.define('Purchase', {
    purchaseDate: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.NOW
    },
    utrNumber: {
        type: DataTypes.STRING(50),
        allowNull: true
    },
    status: {
        type: DataTypes.ENUM('pending', 'approved', 'rejected'),
        defaultValue: 'pending'
    },
    rejectionReason: {
        type: DataTypes.STRING(200),
        allowNull: true
    }
});

// Define relationships
User.hasMany(Purchase);
Purchase.belongsTo(User);
SerialKey.hasMany(Purchase);
Purchase.belongsTo(SerialKey);

module.exports = {
    sequelize,
    User,
    SerialKey,
    Purchase
}; 