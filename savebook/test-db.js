import mongoose from 'mongoose';

async function test() {
  try {
    console.log("URI:", process.env.MONGODB_URI);
    await mongoose.connect(process.env.MONGODB_URI, { bufferCommands: false });
    console.log("Connected to MongoDB successfully!");
  } catch (error) {
    console.error("MongoDB Connection Error:", error);
  } finally {
    process.exit();
  }
}

test();
