import os,sys,datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

def readData(data):
    f = open(data, "rb")
    kdata = f.read()
    f.close()
    return kdata

def create_ec_cert(cert_authority, private_key,csrin):
    one_day = datetime.timedelta(1, 0, 0)
    #open the private key from the CA
    root_key = serialization.load_pem_private_key(
        private_key, password=None    
    )
    #open the public key from the CA
    root_cert = x509.load_pem_x509_certificate(
        cert_authority, default_backend()
    )

    #Generate a new private key
    #https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/ 
    cert_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    
    #Deserialize a certificate signing request (CSR) from PEM encoded data. PEM requests are base64 decoded and have delimiters that look like -----BEGIN CERTIFICATE REQUEST-----. This format is also known as PKCS#10
    #https://cryptography.io/en/latest/x509/reference/
    csr = x509.load_pem_x509_csr(csrin)
    #Build the CA signed cert
    cert = (
        x509.CertificateBuilder()
        #Pull the subject from the CSR
        .subject_name(csr.subject)
        #set the root cert as the issuer
        .issuer_name(root_cert.issuer)
        #Pull the public key from the CSR
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .add_extension(
            #pull the SAN entries from the CSR and apply them to the signed cert
            x509.SubjectAlternativeName(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),
            critical=False,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )
    #pull the commonName value of the CSR and use this to set the filename
    commonname=csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME).__getitem__(0).value
    print(commonname)
    #write the signed cert to disk in pem format
    with open(commonname+".crt", "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
    # Return PEM
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

    cert_key_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, cert_key_pem


ca_pem_key = readData('ca-ecdsa.key')
ca_pem_cert = readData('ca-ecdsa.crt')
csr_pem = readData('sme-tomcat-ECDSA.csr')
#This sample was ran on the basis of using 384bit CSR request. logic should be added to check for key type
a,b =create_ec_cert(ca_pem_cert,ca_pem_key,csr_pem)
print(a)
print(b)