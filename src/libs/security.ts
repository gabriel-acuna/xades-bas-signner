import * as crypto from "node:crypto";
import { Encoding } from "node:crypto";
export function sha1ToBase64(text: string, encoding: Encoding): string {
  const HASH = crypto.createHash("sha1").update(text, encoding).digest("hex");
  const BUFFER = Buffer.from(HASH, "hex");
  return BUFFER.toString("base64");
}

export function hexToBase64(hashHex: string) {
  if (hashHex.length % 2 !== 0) {
    hashHex = "0" + hashHex;
  }
  if (!isHexString(hashHex)) {
    throw new Error("Invalid hex string");
  }
  const buf = Buffer.from(hashHex, "hex");
  return buf.toString("base64");
}

export function bigintToBase64(param: bigint) {
  let hexString = param.toString(16);
  if (hexString.length % 2 !== 0) {
    hexString = "0" + hexString;
  }
  const buffer = Buffer.from(hexString, "hex");
  const base64 = buffer.toString("base64");
  const formatedBase64 = base64.match(/.{1,76}/g)?.join("\n");
  return formatedBase64;
}

export function getRandomValues(min: number = 990, max: number = 9999) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}
export function isHexString(str: string) {
  const hexRegEx = /^[0-9a-fA-F]+$/;
  return hexRegEx.test(str);
}
