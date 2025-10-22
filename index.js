
import 'dotenv/config';
import cors from 'cors';
import express from 'express';
import nodemailer from 'nodemailer';
import { ethers } from 'ethers';
import { create } from 'ipfs-http-client';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// ENV VARIABLES
const {
  PRIVATE_KEY,
  CONTRACT_ADDRESS,
  API_URL,
  IPFS_URL,
  PORT,
  ENCRYPTION_KEY,
  EMAIL_USER,
  EMAIL_PASS,
} = process.env;

// INITIALIZATION
const ipfs = create({ url: IPFS_URL });
const provider = new ethers.providers.JsonRpcProvider(API_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

const __dirname = path.resolve();
const artifactPath = path.join(
  __dirname,
  'artifacts/contracts/SleepPatternStorage.sol/SleepPatternStorage.json'
);
const contractArtifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
const contract = new ethers.Contract(CONTRACT_ADDRESS, contractArtifact.abi, wallet);

const app = express();
app.use(express.json());
app.use(cors());

// EMAIL SETUP
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

// HELPERS

// Verify EIP-191 signature
function verifySignature(message, signature) {
  try {
    return ethers.utils.verifyMessage(message, signature);
  } catch {
    throw new Error('Invalid signature');
  }
}

// AES-256 encryption
function encryptData(data) {
  if (!ENCRYPTION_KEY) return JSON.stringify(data);
  const key = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return JSON.stringify({ iv: iv.toString('hex'), data: encrypted });
}

// AES-256 decryption
function decryptData(encryptedData) {
  if (!encryptedData) return null;
  if (!ENCRYPTION_KEY) return JSON.parse(encryptedData);

  try {
    const parsed = JSON.parse(encryptedData);
    const key = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(parsed.iv, 'hex'));
    let decrypted = decipher.update(parsed.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch {
    return JSON.parse(encryptedData);
  }
}

// Generate ZKP hash
function generateZKPHash(report) {
  const serialized = JSON.stringify(report);
  return crypto.createHash('sha256').update(serialized).digest('hex');
}


/**
 * POST /anomaly
 * Store real-time anomaly detection report with ZKP and optional email alert
 */
app.post('/anomaly', async (req, res) => {
  try {
    const { anomalyReport, userAddress, signature, userEmail } = req.body;

    if (!anomalyReport || !userAddress || !signature)
      return res
        .status(400)
        .json({ error: 'anomalyReport, userAddress, and signature required' });

    const message = `Store anomaly report for ${userAddress} at ${anomalyReport.timestamp}`;
    const recovered = verifySignature(message, signature);
    if (recovered.toLowerCase() !== userAddress.toLowerCase())
      return res.status(401).json({ error: 'Signature verification failed' });

    // Generate ZKP hash backend side
    const zkProofHash = generateZKPHash({
      anomalyScore: anomalyReport.score,
      timestamp: anomalyReport.timestamp,
    });

    // Encrypt and upload to IPFS
    const encryptedPayload = encryptData({ anomalyReport, zkProofHash });
    const { cid } = await ipfs.add(encryptedPayload);
    const ipfsHash = cid.toString();

    // Store hash on-chain
    const tx = await contract.addSleepRecordFor(userAddress, ipfsHash, zkProofHash);
    const receipt = await tx.wait();

    // If anomaly score exceeds threshold, send alert
    if (anomalyReport.isAnomaly && userEmail) {
      await transporter.sendMail({
        from: EMAIL_USER,
        to: userEmail,
        subject: '⚠️ Sleep Anomaly Detected',
        html: `
          <h3>Sleep Anomaly Alert</h3>
          <p>Your recent sleep pattern shows an anomaly.</p>
          <p><b>Score:</b> ${anomalyReport.score}</p>
          <p><b>Time:</b> ${new Date(anomalyReport.timestamp * 1000).toLocaleString()}</p>
          <p><b>IPFS CID:</b> ${ipfsHash}</p>
          <p><b>Proof:</b> ${zkProofHash}</p>
          <p>Please check your health dashboard for more details.</p>
        `,
      });
    }

    const gasUsed = receipt.gasUsed.toString();
    const gasPrice = (receipt.effectiveGasPrice || tx.gasPrice).toString();

    res.json({
      message: '✅ Anomaly record stored successfully',
      ipfsHash,
      zkProofHash,
      transactionHash: tx.hash,
      gasUsed,
      gasPrice,
    });
  } catch (err) {
    console.error('Error in /anomaly:', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /anomaly/:address
 * Retrieve and decrypt all anomaly records for a user
 */
app.get('/anomaly/:address', async (req, res) => {
  try {
    const { address } = req.params;
    if (!ethers.utils.isAddress(address))
      return res.status(400).json({ error: 'Invalid Ethereum address' });

    const records = await contract.getRecordsFor(address);
    const formatted = [];

    for (const r of records) {
      const ipfsHash = r.ipfsHash;
      const timestamp = r.timestamp.toNumber();

      try {
        let chunks = [];
        for await (const chunk of ipfs.cat(ipfsHash)) chunks.push(chunk);
        const dataString = Buffer.concat(chunks).toString('utf8');
        const parsed = decryptData(dataString);

        formatted.push({
          ipfsHash,
          timestamp,
          ...parsed,
        });
      } catch (err) {
        console.error(`Error fetching IPFS data for ${ipfsHash}:`, err);
        formatted.push({
          ipfsHash,
          timestamp,
          error: 'Could not fetch/decrypt IPFS data',
        });
      }
    }

    res.json(formatted);
  } catch (err) {
    console.error('Error in /anomaly/:address:', err);
    res.status(500).json({ error: err.message });
  }
});

// HEALTH CHECK
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    contract: CONTRACT_ADDRESS,
    network: API_URL,
    ipfs: IPFS_URL,
  });
});

// SERVER
const port = PORT || 4000;
app.listen(port, () => {
  console.log(`Backend running on port ${port}`);
  console.log(`Smart Contract: ${CONTRACT_ADDRESS}`);
  console.log(`RPC Network: ${API_URL}`);
});
