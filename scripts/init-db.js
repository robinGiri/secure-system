const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const User = require('../src/models/User');
const Transaction = require('../src/models/Transaction');

// Connect to MongoDB
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/security_app');
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

// Create demo users
const createDemoUsers = async () => {
  try {
    console.log('Creating demo users...');

    // Admin user
    const adminUser = new User({
      username: 'admin',
      email: 'admin@securebank.com',
      password: 'SecureP@ss123!',
      firstName: 'System',
      lastName: 'Administrator',
      role: 'admin',
      isVerified: true,
      balance: 100000
    });

    // Regular user 1
    const user1 = new User({
      username: 'john_doe',
      email: 'john.doe@example.com',
      password: 'UserP@ss123!',
      firstName: 'John',
      lastName: 'Doe',
      role: 'user',
      isVerified: true,
      balance: 5000,
      phoneNumber: '+1234567890',
      address: {
        street: '123 Main St',
        city: 'New York',
        state: 'NY',
        postalCode: '10001',
        country: 'USA'
      }
    });

    // Regular user 2
    const user2 = new User({
      username: 'jane_smith',
      email: 'jane.smith@example.com',
      password: 'UserP@ss456!',
      firstName: 'Jane',
      lastName: 'Smith',
      role: 'user',
      isVerified: true,
      balance: 7500,
      phoneNumber: '+1987654321',
      address: {
        street: '456 Oak Ave',
        city: 'Los Angeles',
        state: 'CA',
        postalCode: '90210',
        country: 'USA'
      }
    });

    // Check if users already exist
    const existingAdmin = await User.findOne({ username: 'admin' });
    const existingUser1 = await User.findOne({ username: 'john_doe' });
    const existingUser2 = await User.findOne({ username: 'jane_smith' });

    if (!existingAdmin) {
      await adminUser.save();
      console.log('✅ Admin user created');
      console.log('   Username: admin');
      console.log('   Password: SecureP@ss123!');
    } else {
      console.log('ℹ️  Admin user already exists');
    }

    if (!existingUser1) {
      await user1.save();
      console.log('✅ User 1 (john_doe) created');
      console.log('   Username: john_doe');
      console.log('   Password: UserP@ss123!');
    } else {
      console.log('ℹ️  User 1 (john_doe) already exists');
    }

    if (!existingUser2) {
      await user2.save();
      console.log('✅ User 2 (jane_smith) created');
      console.log('   Username: jane_smith');
      console.log('   Password: UserP@ss456!');
    } else {
      console.log('ℹ️  User 2 (jane_smith) already exists');
    }

    return { adminUser: existingAdmin || adminUser, user1: existingUser1 || user1, user2: existingUser2 || user2 };
  } catch (error) {
    console.error('Error creating demo users:', error);
    throw error;
  }
};

// Create demo transactions
const createDemoTransactions = async (users) => {
  try {
    console.log('\nCreating demo transactions...');

    const existingTransactions = await Transaction.countDocuments();
    if (existingTransactions > 0) {
      console.log('ℹ️  Demo transactions already exist');
      return;
    }

    // Transaction 1: Deposit for user1
    const transaction1 = new Transaction({
      type: 'deposit',
      amount: 1000,
      description: 'Initial deposit',
      toAccount: users.user1._id,
      authenticationMethod: 'password',
      ipAddress: '127.0.0.1',
      userAgent: 'Demo Script',
      status: 'completed',
      processedAt: new Date(),
      createdBy: users.user1._id
    });

    // Transaction 2: Transfer from user1 to user2
    const transaction2 = new Transaction({
      type: 'transfer',
      amount: 250,
      description: 'Payment for services',
      fromAccount: users.user1._id,
      toAccount: users.user2._id,
      authenticationMethod: 'mfa',
      ipAddress: '127.0.0.1',
      userAgent: 'Demo Script',
      status: 'completed',
      processedAt: new Date(),
      createdBy: users.user1._id,
      balanceBefore: {
        fromAccount: users.user1.balance,
        toAccount: users.user2.balance
      },
      balanceAfter: {
        fromAccount: users.user1.balance - 250,
        toAccount: users.user2.balance + 250
      }
    });

    // Transaction 3: Withdrawal for user2
    const transaction3 = new Transaction({
      type: 'withdrawal',
      amount: 500,
      description: 'ATM withdrawal',
      fromAccount: users.user2._id,
      authenticationMethod: 'password',
      ipAddress: '192.168.1.100',
      userAgent: 'Demo Script',
      status: 'completed',
      processedAt: new Date(),
      createdBy: users.user2._id
    });

    // Calculate risk scores
    transaction1.calculateRiskScore();
    transaction2.calculateRiskScore();
    transaction3.calculateRiskScore();

    // Generate checksums
    transaction1.generateChecksum();
    transaction2.generateChecksum();
    transaction3.generateChecksum();

    await transaction1.save();
    await transaction2.save();
    await transaction3.save();

    console.log('✅ Demo transactions created:');
    console.log(`   - Deposit: $${transaction1.amount} (${transaction1.transactionId})`);
    console.log(`   - Transfer: $${transaction2.amount} (${transaction2.transactionId})`);
    console.log(`   - Withdrawal: $${transaction3.amount} (${transaction3.transactionId})`);

  } catch (error) {
    console.error('Error creating demo transactions:', error);
    throw error;
  }
};

// Main initialization function
const initializeDatabase = async () => {
  try {
    console.log('🚀 Initializing database with demo data...\n');

    await connectDB();
    
    const users = await createDemoUsers();
    await createDemoTransactions(users);

    console.log('\n✅ Database initialization completed successfully!');
    console.log('\n📝 Demo Accounts Created:');
    console.log('┌─────────────┬──────────────────────┬──────────────────┬──────────┐');
    console.log('│ Username    │ Email                │ Password         │ Role     │');
    console.log('├─────────────┼──────────────────────┼──────────────────┼──────────┤');
    console.log('│ admin       │ admin@securebank.com │ SecureP@ss123!   │ admin    │');
    console.log('│ john_doe    │ john.doe@example.com │ UserP@ss123!     │ user     │');
    console.log('│ jane_smith  │ jane.smith@example.com│ UserP@ss456!     │ user     │');
    console.log('└─────────────┴──────────────────────┴──────────────────┴──────────┘');
    console.log('\n🌐 You can now start the application with: npm run dev');
    console.log('🔗 Access the application at: http://localhost:3000');

  } catch (error) {
    console.error('❌ Database initialization failed:', error);
  } finally {
    await mongoose.connection.close();
    console.log('\n🔌 Database connection closed');
    process.exit(0);
  }
};

// Run the initialization
if (require.main === module) {
  initializeDatabase();
}

module.exports = { initializeDatabase, createDemoUsers, createDemoTransactions };
