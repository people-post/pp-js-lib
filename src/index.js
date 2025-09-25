import {ml_dsa44} from '@noble/post-quantum/ml-dsa.js';
import crypto from 'crypto';
import fs from "node:fs";
import path from "node:path";

function readJsonFile(filePath) {
  try {
    const data = fs.readFileSync(filePath, "utf8");
    return JSON.parse(data);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

function hashFile(filePath, algorithm = 'sha256') {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash(algorithm);
    const stream = fs.createReadStream(filePath);

    stream.on(
        'error',
        (err) => { reject(new Error(`Error reading file: ${err.message}`)); });

    stream.on('data', (chunk) => { hash.update(chunk); });

    stream.on('end', () => { resolve(hash.digest('hex')); });
  });
}

function makeDirs(dirPath) {
  if (!fs.existsSync(dirPath)) {
    try {
      fs.mkdirSync(dirPath, {recursive : true});
      console.log("Data dir created:", dirPath);
    } catch (err) {
      console.error("Error creating directory:", err);
      process.exit(1);
    }
  }
}

function makeApiResponse(res, jd) {
  return res.status(200)
      .header('Content-Type', 'application/json')
      .send(JSON.stringify(jd));
}

function makeResponse(res, jd) { return makeApiResponse(res, {data : jd}); }

function makeErrorResponse(res, type, code, msg) {
  return makeApiResponse(res, {error : {type : type, code : code, data : msg}});
}

function makeUserErrorResponse(res, code) {
  return makeErrorResponse(res, "USR", code, null);
}

function makeQuotaErrorResponse(res, code) {
  return makeErrorResponse(res, "QTA", code, null);
}

function makeLimitationResponse(res, code) {
  return makeErrorResponse(res, "LMT", code, null);
}

function makeDevErrorResponse(res, msg) {
  return makeErrorResponse(res, "DEV", null, msg);
}

function verifyUint8ArraySignature(d, pubKey, sig) {
  const p = Uint8Array.from(Buffer.from(pubKey, 'hex'));
  const s = Uint8Array.from(Buffer.from(sig, 'hex'));
  return ml_dsa44.verify(s, d, p);
}

function verifySignature(data, pubKey, sig) {
  return verifyUint8ArraySignature(Uint8Array.from(Buffer.from(data, 'utf8')),
                                   pubKey, sig);
}

async function authCheck(req, res, db) {
  let token = req.headers.authorization?.split('Bearer ')?.pop();
  let u = db.getUserById(token);
  if (!u) {
    throw new Error("Not authorized");
  }
  req.g.user = u;
}

export {
  readJsonFile,
  hashFile,
  makeDirs,
  makeResponse,
  makeUserErrorResponse,
  makeQuotaErrorResponse,
  makeLimitationResponse,
  makeDevErrorResponse,
  verifySignature,
  verifyUint8ArraySignature,
  authCheck
}
