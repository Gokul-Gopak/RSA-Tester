// server.js
const app = require('express')();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const port = process.env.PORT || 8080;

const crypto = require('crypto');

// Generate a 32-byte AES key
const encryptionKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

// Handle incoming socket connections
io.on('connection', (socket) => {
    console.log('a user connected');

    // Handle incoming new user event
    socket.on("new user", (username) => {
        console.log(`User ${username} connected`);
        socket.username = username;
    });

    // Handle incoming chat messages
    socket.on('chat message', (message) => {
        const username = socket.username;
        // Create a Cipher object with the AES algorithm and CBC mode
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);

        // Encrypt the message using the AES key
        let aes_encrypted = cipher.update(message, 'utf8', 'base64');
        aes_encrypted += cipher.final('base64');

        // console.log('encrypted message: ' + aes_encrypted);


        //RSA stuff
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
            // The standard secure default length for RSA keys is 2048 bits
            modulusLength: 2048,
        });

        const pubkey = publicKey.export({
            type: "spki",
            format: "pem",
        });
        // console.log("pubkey : ", pubkey);
        const privkey = privateKey.export({
            type: "pkcs8",
            format: "pem",
        });
        // console.log("privkey : ", privkey);
        const RSAmessage = encryptionKey;
        const encryptedData = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            // We convert the data string to a buffer using `Buffer.from`
            Buffer.from(RSAmessage)
        );

        // console.log("\nRSA Encrypted data:", encryptedData.toString("base64"));

        const decryptedData = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            encryptedData
        );

        // console.log("\nRSA Decrypted data:", decryptedData.toString());

        // Create a Decipher object with the AES algorithm and CBC mode
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);

        // Decrypt the message using the AES key
        let aes_decrypted = decipher.update(aes_encrypted, 'base64', 'utf8');
        aes_decrypted += decipher.final('utf8');

        console.log('decrypted message: ' + aes_decrypted);

        // Broadcast both the encrypted and decrypted messages to all connected clients
        // io.emit('chat message', { encrypted: aes_encrypted, decrypted: aes_decrypted });
        io.emit("chat message", { username: username, decrypted: aes_decrypted });
    });

    // Handle socket disconnections
    socket.on('disconnect', () => {
        console.log('user disconnected');
    });
});

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});
// Start the server
http.listen(port, () => {
    console.log(`listening on *:${port}`);
});