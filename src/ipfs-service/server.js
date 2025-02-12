import express from "express";
import { create } from "@web3-storage/w3up-client";
import fs from "fs";

const app = express();
const port = 3000;

app.use(express.json());

const didSpace = 'did:key:z6MkiJ5Q5F6kp9LSWzYtXfNc49CjYwUy5sBMPsFow935VqZd';
const folderPath = '../../tmp/'

/**
 * Function to upload a file from disk to the storage service.
 *
 * @param {string} fileName - The name of the file in the folderPath.
 * @returns {Promise<string|null>} - The CID of the uploaded file, or null on error.
 */

async function uploadFile(fileName) {
    try 
    {
        const client = await create();
        console.log("🔑 Logging in...");
        const account = await client.login("jipianu_mihnea@yahoo.com");
        console.log("✅ Logged in with account:", account.did());


        client.setCurrentSpace(didSpace);

        const filePath = folderPath+fileName;
        const fileBuffer = fs.readFileSync(filePath);
        const file = new Blob([fileBuffer], { type: "text/plain" });
        const cid = await client.uploadFile(file, {
            retries: 3, // Retry up to 3 times if it fails
            concurrentRequests: 5, // Allow multiple parallel uploads
            shardSize: null // Customize shard size (default: 256KB)
        });

        console.log(`📤 Uploaded file with CID: ${cid}`);

        return cid;

    } catch (error) {
        console.error("❌ Error:", error.message);
        throw error;
    }
}

app.post("/upload", async (req, res) => {
    // Expect a JSON payload: { "fileName": "README.md" }
    const { fileName } = req.body;
    if (!fileName) {
      return res.status(400).json({ error: "Missing fileName in request body" });
    }
    try {
      // Call the uploadFile function
      const cid = await uploadFile(fileName);
      return res.status(200).json({ cid });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  });

  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
