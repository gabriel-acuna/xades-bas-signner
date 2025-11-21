import { FileManager } from "./files";
import { getPCK12CertInfo } from "./credentials";
import { sha1ToBase64, toBase64String, toSha1 } from "./security";
export async function getP12(path: string) {
  const fileManager = new FileManager();
  try {
    await fileManager.openFile(path);
    return fileManager.getFile();
  } catch (error) {
    throw new Error("Error reading P12 file: " + error);
  }
}

export async function getXML(path: string) {
  const fileManager = new FileManager();
  try {
    await fileManager.openFile(path);
  } catch (error) {
    throw new Error("Error reading XML file: " + error);
  }
  return fileManager.toString("utf-8");
}

function getSignedPropertiesNode(params: {
  signatureNumber: number;
  signedPropertiesNumber: number;
  signingTime: string;
  digestValue: string;
  issuerName: string;
  issuerSerialNumber: number;
  referenceIdNumber: number;
}) {
  return (
    `<etsi:SignedProperties Id="Signature${params.signatureNumber} SignedProperties${params.signedPropertiesNumber}">` +
    `<etsi:SignedSignatureProperties>` +
    `<etsi:SignedTime>${params.signingTime}</etsi:SignedTime>` +
    `<etsi:SigningCertificate>` +
    `<etsi:Cert>` +
    `<etsi:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1">` +
    `<etsi:DigestValue>${params.digestValue}</etsi:DigestValue></etsi:CertDigest>` +
    `<etsi:IssuerSerial>` +
    `<ds:X509IssuerName>${params.issuerName}</ds:X509IssuerName>` +
    `<ds:X509SerialNumber>${params.issuerSerialNumber}</ds:X509SerialNumber>` +
    `</etsi:IssuerSerial>` +
    `</etsi:Cert>` +
    `</etsi:SigningCertificate>` +
    `<etsi:SignedDataObjectProperties>` +
    `<etsi:DataObjectFormat ObjectReference="#Reference-ID=${params.referenceIdNumber}">` +
    `<etsi:Description>contenido comprobante</etsi:Description>` +
    `<etsi:MimeType>text/xml</etsi:MimeType>` +
    `</etsi:DataObjectFormat>` +
    `</etsi:SignedDataObjectProperties>` +
    `</etsi:SignedProperties>`
  );
}
function getKeyInfoNode(params: {
  certificateNumber: number;
  certificateX509: string;
  modulus: string;
  exponent: string;
}) {
  return (
    `<ds:KeyInfo Id="Certificate${params.certificateNumber}">` +
    `\n<ds:X509Data>` +
    `\n<ds:X509Certificate>\n${params.certificateX509}\n</ds:X509Certificate>` +
    `\n</ds:X509Data>` +
    `\n</ds:KeyValue>\n<ds:RSAKeyValue>\n<ds:Modulus>\n${params.modulus}\n</ds:Modulus>` +
    `\n<ds:Exponent>\n${params.exponent}</ds:Exponent>` +
    `\n</ds:RSAKeyValue>` +
    `\n</ds:KeyInfo>`
  );
}
function getSignedInfoNode(params: {
  signedInfoNumber: number;
  signedPropertiesIdNumber: number;
  signatureNumber: number;
  signedPropertiesNumber: number;
  sha1SignedProperties: string;
  certificateNumber: number;
  sha1KeyInfo: string;
  referenceIdNumber: number;
  sha1Xml: string;
}) {
  return (
    `<ds:SignedInfo Id="Signature-SignedInfo${params.signedInfoNumber}">` +
    `\n<ds:CanonicalizationMethod> Algorithm=”http://www.w3.org/TR/2001/REC-xml-c14n20010315”></ds:CanonicalizationMethod>` +
    `\n<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod>` +
    `\n<ds:Reference Id="SignedPropertiedID${params.signedPropertiesIdNumber}"> Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature${params.signatureNumber}-SignedProperties${params.signedPropertiesNumber}">` +
    `\n<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>` +
    `\n<ds:DigestValue>${params.sha1SignedProperties}</ds:DigestValue>` +
    `\n</ds:Reference>` +
    `\n<ds:Reference URI="Certificate${params.certificateNumber}">` +
    `\n<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>` +
    `\n<ds:DigestValue>${params.sha1KeyInfo}</ds:DigestValue>` +
    `\n</ds:Reference>` +
    `\n<ds:Reference Id="Reference-ID-${params.referenceIdNumber}" URI="#comprobante">` +
    `\n<ds:Transforms>` +
    `\n<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>` +
    `\n</ds:Transforms>` +
    `\n<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>` +
    `\n<ds:DigestValue>${params.sha1Xml}</ds:DigestValue>` +
    `\n</ds:Reference>` +
    `</ds:SignedInfo`
  );
}
function getSignatureObject(params: {
  signatureNumber: number;
  objectNumber: number;
  signedInfo: string;
}) {
  const objectSignature =
    `<ds:Object Id="Signature${params.signatureNumber}-Object${params.objectNumber}">` +
    `<etsi:QualifyingProperties Target="#Signature${params.signatureNumber}">` +
    `${params.signedInfo}` +
    `</etsi:QualifyingProperties></ds:Object>`;
  return objectSignature;
}
function getSignatureNode(params: {
  namespaces: string;
  signatureNumber: number;
  signedInfoNode: string;
  signatureValueNode: string;
  keyInfoNode: string;
  objectSignarureNode: string;
}) {
  const signatureNode =
    `\n<ds:Signature ${params.namespaces} Id="Signature${params.signatureNumber}">` +
    `\n${params.signedInfoNode}` +
    `\n${params.signatureValueNode}` +
    `\n${params.keyInfoNode}` +
    `\n${params.objectSignarureNode}` +
    `</ds:Signature>`;
  return signatureNode;
}
function nodeCanonicalization(params: {
  content: string;
  nodeName: string;
  namespaces: string;
}) {
  return params.content.replace(
    params.nodeName,
    `${params.nodeName} ${params.namespaces}`
  );
}
function addSignatureNode(params: {
  xml: string;
  rootElement: string;
  signatureNode: string;
}) {
  const { xml, rootElement, signatureNode } = params;
  return xml.replace(`</${rootElement}>`, `${signatureNode}</${rootElement}>`);
}
export async function sing(params: {
  p12Path: string;
  p12Password: string;
  rootElement: string;
  xmlPath?: string;
  xmlString?: string;
}) {
  const { p12Path, p12Password, xmlPath, xmlString } = params;
  if (!xmlPath && !xmlString) {
    throw new Error("Either xmlPath or xmlString must be provided.");
  }
  const p12Buffer = await getP12(p12Path);
  let xmlData = "";
  xmlData += xmlPath ? await getXML(xmlPath) : xmlString;
  xmlData = xmlData
    .replace(/\s+/g, " ")
    .trim()
    .replace(/(?=<\>)(\r?\n)|(\r?\n)(?=\<\/) /g, "")
    .trim()
    .replace(/(?=<\>)(\s*)/g, "")
    .replace(/\t|\r/g, "");

  const arayuint8 = new Uint8Array(p12Buffer!);
  let certInfo = getPCK12CertInfo(arayuint8, p12Password);

  const sha1Xml = sha1ToBase64(
    xmlData.replace(`<?xml version="1.0" encoding="UTF-8"?>`, ""),
    "utf8"
  );
  const namespaces =
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#namespace xmlns:estsi="http://uri.etsi.org/01903/v1.3.2#"';

  let signedProperties = getSignedPropertiesNode({
    signatureNumber: certInfo.radomValues.signatureNumber,
    signedPropertiesNumber: certInfo.radomValues.signedPropertiesNumber,
    signingTime: certInfo.certInfo.signingTime,
    digestValue: certInfo.certInfo.digestValue,
    issuerName: certInfo.certInfo.issuerName!,
    issuerSerialNumber: certInfo.certInfo.issuerSerialNumber,
    referenceIdNumber: certInfo.radomValues.referenceIdNumber,
  });

  const signedPropertiesCanonicalized = nodeCanonicalization({
    content: signedProperties,
    nodeName: "<etsi:SignedProperties",
    namespaces,
  });

  const sha1SignedProperties = sha1ToBase64(
    signedPropertiesCanonicalized,
    "utf8"
  );

  const keyInfo = getKeyInfoNode({
    certificateNumber: certInfo.radomValues.certificateNumber,
    certificateX509: certInfo.certInfo.certificateX509,
    modulus: certInfo.certInfo.modulus!,
    exponent: certInfo.certInfo.exponent,
  });
  const keyInfoCanonicalized = nodeCanonicalization({
    content: keyInfo,
    nodeName: "<ds:KeyInfo",
    namespaces,
  });
  const sha1KeyInfo = sha1ToBase64(keyInfoCanonicalized, "utf-8");

  const signedInfo = getSignedInfoNode({
    signedInfoNumber: certInfo.radomValues.signedInfoNumber,
    signedPropertiesIdNumber: certInfo.radomValues.signedPropertiesIdNumber,
    sha1SignedProperties,
    certificateNumber: certInfo.radomValues.certificateNumber,
    sha1KeyInfo,
    referenceIdNumber: certInfo.radomValues.referenceIdNumber,
    sha1Xml,
    signatureNumber: certInfo.radomValues.signatureNumber,
    signedPropertiesNumber: certInfo.radomValues.signedPropertiesNumber,
  });
  const signedInfoCanonicalized = nodeCanonicalization({
    content: signedInfo,
    nodeName: "<ds:SignedInfo",
    namespaces,
  });
  const md = toSha1(signedInfoCanonicalized, "utf8");
  const signatureValue =
    toBase64String(certInfo.certInfo.key.sign(md))
      .match(/.{1,76}/g)
      ?.join("\n") ?? "";
  const signatureValueNode =
    `\n<ds:SignatureValue Id="SignatureValue${certInfo.radomValues.signatureValueNumber}">` +
    `${signatureValue}\n</ds:SignatureValue>`;
  const objectSignature = getSignatureObject({
    signatureNumber: certInfo.radomValues.signatureNumber,
    objectNumber: certInfo.radomValues.objectNumber,
    signedInfo,
  });
  const signatureNode = getSignatureNode({
    namespaces,
    signatureNumber: certInfo.radomValues.signatureNumber,
    signedInfoNode: signedInfo,
    signatureValueNode,
    keyInfoNode: keyInfo,
    objectSignarureNode: objectSignature,
  });
  addSignatureNode({
    xml: xmlData,
    rootElement: params.rootElement,
    signatureNode,
  });
}
