const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI || !JWT_SECRET) {
    console.error("FATAL ERROR: MONGODB_URI and JWT_SECRET must be defined in environment variables.");
    process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(MONGO_URI)
    .then(() => console.log("MongoDB connected successfully."))
    .catch(err => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    coins: { type: Number, default: 10000 },
    bio: { type: String, default: "No bio set." },
    pfp: { type: String, default: "https://i.imgur.com/8bzvETr.png" },
    online: { type: Boolean, default: false },
    isAdmin: { type: Boolean, default: false },
    isOwner: { type: Boolean, default: false },
    timeoutUntil: { type: Date, default: null },
    lastDailyClaim: { type: Date, default: null }
});
const messageSchema = new mongoose.Schema({
    username: String,
    message: String,
    timestamp: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

const blackjackGames = new Map();
const minesGames = new Map();

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'Access denied.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        res.status(400).json({ message: 'Invalid token.' });
    }
};

const adminAuthenticate = async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (user && (user.isAdmin || user.isOwner)) {
        next();
    } else {
        res.status(403).json({ message: 'Forbidden: Admin access required.' });
    }
};
const ownerAuthenticate = async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (user && user.isOwner) {
        next();
    } else {
        res.status(403).json({ message: 'Forbidden: Owner access required.' });
    }
};

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Username and password are required." });
        if (await User.findOne({ username: username.toLowerCase() })) return res.status(400).json({ message: "Username already taken." });
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username: username.toLowerCase(), password: hashedPassword });
        await user.save();
        res.status(201).json({ message: "User registered successfully." });
    } catch (error) { res.status(500).json({ message: "Server error during registration." }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
    } catch (error) { res.status(500).json({ message: "Server error during login." }); }
});

app.get('/api/profile', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
});

app.post('/api/profile/update', authenticateToken, async (req, res) => {
    const { bio, pfp } = req.body;
    const updateData = {};
    if (bio) updateData.bio = bio;
    if (pfp) updateData.pfp = pfp;
    await User.findByIdAndUpdate(req.user.id, updateData);
    res.status(200).json({ message: 'Profile updated' });
});

app.get('/api/user/:username', async (req, res) => {
    const user = await User.findOne({ username: req.params.username.toLowerCase() }).select('username bio pfp');
    res.json(user || { message: 'User not found' });
});

const getCardValue = c => { if (['J', 'Q', 'K'].includes(c.value)) return 10; if (c.value === 'A') return 11; return parseInt(c.value); };
const getHandValue = h => { let v = h.reduce((s, c) => s + getCardValue(c), 0); let a = h.filter(c => c.value === 'A').length; while (v > 21 && a > 0) { v -= 10; a--; } return v; };
app.post('/api/blackjack/start', authenticateToken, async (req, res) => { const { bet } = req.body; const user = await User.findById(req.user.id); if (blackjackGames.has(req.user.id)) return res.status(400).json({ message: "Finish your current game." }); if (!bet || bet <= 0 || user.coins < bet) return res.status(400).json({ message: "Invalid bet." }); user.coins -= bet; await user.save(); await broadcastOnlineUsers(); const deck = ['H', 'D', 'C', 'S'].flatMap(s => ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'].map(v => ({ suit: s, value: v }))).sort(() => .5 - Math.random()); const pHand = [deck.pop(), deck.pop()], dHand = [deck.pop(), deck.pop()]; const gState = { deck, playerHand: pHand, dealerHand: dHand, bet, status: 'playing' }; blackjackGames.set(req.user.id, gState); if (getHandValue(pHand) === 21) { const w = bet * 2.5; user.coins += w; await user.save(); blackjackGames.delete(req.user.id); await broadcastOnlineUsers(); return res.json({ status: `Blackjack! Win ${w}`, playerHand: pHand, dealerHand: dHand, playerValue: 21, dealerValue: getHandValue(dHand), newBalance: user.coins }); } res.json({ status: 'playing', playerHand: pHand, dealerHand: [dHand[0], { suit: '?', value: '?' }], playerValue: getHandValue(pHand), newBalance: user.coins }); });
app.post('/api/blackjack/action', authenticateToken, async (req, res) => { const { action } = req.body; const game = blackjackGames.get(req.user.id); if (!game) return res.status(404).json({ message: "No active game." }); const user = await User.findById(req.user.id); let pVal = getHandValue(game.playerHand); if (action === 'hit') { game.playerHand.push(game.deck.pop()); pVal = getHandValue(game.playerHand); if (pVal > 21) { blackjackGames.delete(req.user.id); await broadcastOnlineUsers(); return res.json({ status: `Bust! Lost ${game.bet}`, playerHand: game.playerHand, dealerHand: game.dealerHand, playerValue: pVal, newBalance: user.coins }); } blackjackGames.set(req.user.id, game); return res.json({ status: 'playing', playerHand: game.playerHand, dealerHand: [game.dealerHand[0],{suit:'?',value:'?'}], playerValue: pVal }); } if (action === 'stand') { while (getHandValue(game.dealerHand) < 17) game.dealerHand.push(game.deck.pop()); const dVal = getHandValue(game.dealerHand); pVal = getHandValue(game.playerHand); let msg = '', w = 0; if (dVal > 21 || pVal > dVal) { w = game.bet * 2; msg = `You win ${w}`; user.coins += w; } else if (pVal < dVal) { msg = `Dealer wins. Lost ${game.bet}`; } else { w = game.bet; msg = `Push. Bet of ${w} returned`; user.coins += w; } await user.save(); blackjackGames.delete(req.user.id); await broadcastOnlineUsers(); return res.json({ status: msg, playerHand: game.playerHand, dealerHand: game.dealerHand, playerValue: pVal, dealerValue: dVal, newBalance: user.coins }); } });
app.post('/api/mines/start', authenticateToken, async (req, res) => { const { bet, minesCount } = req.body; const user = await User.findById(req.user.id); if (minesGames.has(req.user.id)) return res.status(400).json({ message: "Finish your current game." }); if (!bet || bet <= 0 || user.coins < bet) return res.status(400).json({ message: "Invalid bet." }); if (![3, 5, 8, 10].includes(minesCount)) return res.status(400).json({ message: "Invalid mine count." }); user.coins -= bet; await user.save(); await broadcastOnlineUsers(); const mines = new Set(); while (mines.size < minesCount) mines.add(Math.floor(Math.random() * 25)); minesGames.set(req.user.id, { bet, mines: Array.from(mines), clicks: 0, mult: { 3: 1.15, 5: 1.3, 8: 1.5, 10: 1.8 }[minesCount] }); res.json({ newBalance: user.coins }); });
app.post('/api/mines/click', authenticateToken, async (req, res) => { const { index } = req.body; const game = minesGames.get(req.user.id); if (!game) return res.status(404).json({ message: "No active game." }); if (game.mines.includes(index)) { minesGames.delete(req.user.id); return res.json({ gameOver: true, message: `Boom! You lost ${game.bet}`, minePositions: game.mines }); } game.clicks++; const profit = game.bet * Math.pow(game.mult, game.clicks) - game.bet; minesGames.set(req.user.id, game); res.json({ gameOver: false, profit: Math.floor(profit), nextMultiplier: Math.pow(game.mult, game.clicks + 1) }); });
app.post('/api/mines/cashout', authenticateToken, async (req, res) => { const game = minesGames.get(req.user.id); if (!game || game.clicks === 0) return res.status(400).json({ message: "No game or clicks to cashout." }); const winnings = Math.floor(game.bet * Math.pow(game.mult, game.clicks)); const user = await User.findById(req.user.id); user.coins += winnings; await user.save(); minesGames.delete(req.user.id); await broadcastOnlineUsers(); res.json({ message: `Cashed out ${winnings} coins!`, newBalance: user.coins }); });
app.post('/api/roulette/spin', authenticateToken, async (req, res) => { const { bets } = req.body; const user = await User.findById(req.user.id); if (!bets || typeof bets !== 'object' || Object.keys(bets).length === 0) return res.status(400).json({ message: "No bets placed." }); let totalBet = 0; for (const betType in bets) { for (const value in bets[betType]) { const amount = parseInt(bets[betType][value], 10); if (isNaN(amount) || amount <= 0) return res.status(400).json({ message: "Invalid bet amount."}); totalBet += amount; } } if (user.coins < totalBet) return res.status(400).json({ message: "Insufficient coins." }); user.coins -= totalBet; await user.save(); const ROULETTE_NUMBERS = [0, 32, 15, 19, 4, 21, 2, 25, 17, 34, 6, 27, 13, 36, 11, 30, 8, 23, 10, 5, 24, 16, 33, 1, 20, 14, 31, 9, 22, 18, 29, 7, 28, 12, 35, 3, 26]; const ROULETTE_COLORS = { 0: 'green', 1: 'red', 2: 'black', 3: 'red', 4: 'black', 5: 'red', 6: 'black', 7: 'red', 8: 'black', 9: 'red', 10: 'black', 11: 'black', 12: 'red', 13: 'black', 14: 'red', 15: 'black', 16: 'red', 17: 'black', 18: 'red', 19: 'red', 20: 'black', 21: 'red', 22: 'black', 23: 'red', 24: 'black', 25: 'red', 26: 'black', 27: 'red', 28: 'black', 29: 'black', 30: 'red', 31: 'black', 32: 'red', 33: 'black', 34: 'red', 35: 'black', 36: 'red' }; const winningNumber = ROULETTE_NUMBERS[Math.floor(Math.random() * ROULETTE_NUMBERS.length)]; const winningColor = ROULETTE_COLORS[winningNumber]; let winnings = 0; const payoutMultipliers = { number: 36, color: 2, dozen: 3, column: 3, parity: 2, range: 2 }; if (bets.number && bets.number[winningNumber]) { winnings += bets.number[winningNumber] * payoutMultipliers.number; } if (bets.color && bets.color[winningColor]) { winnings += bets.color[winningColor] * payoutMultipliers.color; } if (winningNumber > 0) { if (bets.parity) { if (winningNumber % 2 === 0 && bets.parity.even) winnings += bets.parity.even * payoutMultipliers.parity; if (winningNumber % 2 !== 0 && bets.parity.odd) winnings += bets.parity.odd * payoutMultipliers.parity; } if (bets.range) { if (winningNumber >= 1 && winningNumber <= 18 && bets.range['1-18']) winnings += bets.range['1-18'] * payoutMultipliers.range; if (winningNumber >= 19 && winningNumber <= 36 && bets.range['19-36']) winnings += bets.range['19-36'] * payoutMultipliers.range; } if (bets.dozen) { if (winningNumber >= 1 && winningNumber <= 12 && bets.dozen['1st']) winnings += bets.dozen['1st'] * payoutMultipliers.dozen; if (winningNumber >= 13 && winningNumber <= 24 && bets.dozen['2nd']) winnings += bets.dozen['2nd'] * payoutMultipliers.dozen; if (winningNumber >= 25 && winningNumber <= 36 && bets.dozen['3rd']) winnings += bets.dozen['3rd'] * payoutMultipliers.dozen; } if (bets.column) { const column = (winningNumber - 1) % 3 + 1; if (column === 1 && bets.column['1st']) winnings += bets.column['1st'] * payoutMultipliers.column; if (column === 2 && bets.column['2nd']) winnings += bets.column['2nd'] * payoutMultipliers.column; if (column === 3 && bets.column['3rd']) winnings += bets.column['3rd'] * payoutMultipliers.column; } } if (winnings > 0) { user.coins += winnings; await user.save(); } await broadcastOnlineUsers(); res.json({ winningNumber, winningColor, winnings, newBalance: user.coins, message: `Landed on ${winningNumber} ${winningColor}. You won ${winnings.toLocaleString()}!` }); });

// --- ADMIN & OWNER ROUTES ---
app.get('/api/admin/get-users', authenticateToken, adminAuthenticate, async (req, res) => { try { const users = await User.find({}).select('username').sort({ username: 1 }); res.json(users.map(u => u.username)); } catch (error) { res.status(500).json({ message: 'Server error fetching users.' }); }});
app.post('/api/admin/claim-daily', authenticateToken, adminAuthenticate, async (req, res) => { try { const user = await User.findById(req.user.id); const twentyFourHours = 24 * 60 * 60 * 1000; if (user.lastDailyClaim && (new Date() - new Date(user.lastDailyClaim) < twentyFourHours)) { return res.status(400).json({ message: 'You have already claimed your daily reward.' }); } user.coins += 100000; user.lastDailyClaim = new Date(); await user.save(); await broadcastOnlineUsers(); res.json({ message: 'You have claimed 100,000 coins!', newBalance: user.coins, lastDailyClaim: user.lastDailyClaim }); } catch (error) { res.status(500).json({ message: 'Server error claiming reward.' }) }});
app.post('/api/owner/clear-chat', authenticateToken, ownerAuthenticate, async (req, res) => { try { await Message.deleteMany({}); io.emit('chat_cleared'); res.json({ message: 'Chat has been cleared.' }); } catch (error) { res.status(500).json({ message: 'Server error clearing chat.' }) }});
app.post('/api/admin/timeout-user', authenticateToken, adminAuthenticate, async (req, res) => { try { const { username, duration } = req.body; const requester = await User.findById(req.user.id); if (!username || !duration) return res.status(400).json({ message: 'Username and duration are required.' }); const targetUser = await User.findOne({ username: username.toLowerCase() }); if (!targetUser) return res.status(404).json({ message: 'User not found.' }); if (targetUser.isOwner || (targetUser.isAdmin && !requester.isOwner)) return res.status(403).json({ message: 'You do not have permission to timeout this user.' }); targetUser.timeoutUntil = new Date(Date.now() + duration * 60 * 1000); await targetUser.save(); res.json({ message: `${username} has been timed out for ${duration} minutes.` }); } catch (error) { res.status(500).json({ message: 'Server error timing out user.' }) }});
app.post('/api/owner/give-coins', authenticateToken, ownerAuthenticate, async (req, res) => { try { const { username, amount } = req.body; const parsedAmount = parseInt(amount, 10); if (!username || isNaN(parsedAmount)) return res.status(400).json({ message: 'Username and a valid amount are required.' }); const targetUser = await User.findOneAndUpdate({ username: username.toLowerCase() }, { $inc: { coins: parsedAmount } }, { new: true }); if (!targetUser) return res.status(404).json({ message: 'User not found.' }); await broadcastOnlineUsers(); res.json({ message: `Successfully gave ${parsedAmount.toLocaleString()} coins to ${username}. Their new balance is ${targetUser.coins.toLocaleString()}.`}); } catch (error) { res.status(500).json({ message: 'Server error giving coins.' }) }});
app.post('/api/owner/set-admin', authenticateToken, ownerAuthenticate, async (req, res) => { try { const { username, isAdmin } = req.body; if (!username || typeof isAdmin !== 'boolean') return res.status(400).json({ message: 'Username and isAdmin status (true/false) are required.' }); const targetUser = await User.findOneAndUpdate({ username: username.toLowerCase() }, { $set: { isAdmin: isAdmin } }, { new: true }); if (!targetUser) return res.status(404).json({ message: 'User not found.' }); res.json({ message: `${username}'s admin status has been set to ${isAdmin}.` }); } catch (error) { res.status(500).json({ message: 'Server error setting admin status.' }) }});

// --- SOCKET.IO LOGIC ---
io.use(async (socket, next) => { const token = socket.handshake.auth.token; if (!token) return next(new Error("Authentication error")); try { const decoded = jwt.verify(token, JWT_SECRET); const user = await User.findById(decoded.id).select('username timeoutUntil').lean(); if (!user) return next(new Error("User not found")); socket.userId = user._id.toString(); socket.username = user.username; socket.timeoutUntil = user.timeoutUntil; next(); } catch (err) { return next(new Error("Authentication error")); }});
io.on('connection', async (socket) => { console.log(`User Authenticated & Connected: ${socket.username}`); try { await User.findByIdAndUpdate(socket.userId, { online: true }); await broadcastOnlineUsers(); const lastMessages = await Message.find().sort({ timestamp: -1 }).limit(50).lean(); const messagesWithPfps = await Promise.all(lastMessages.map(async msg => { const sender = await User.findOne({ username: msg.username }).select('pfp').lean(); return { ...msg, pfp: sender ? sender.pfp : 'https://i.imgur.com/8bzvETr.png' }; })); socket.emit('chat_history', messagesWithPfps.reverse()); } catch (err) { console.error("Error during socket connection setup:", err); }
    socket.on('chat_message', async (msg) => { const user = await User.findById(socket.userId).select('timeoutUntil'); if (user.timeoutUntil && new Date(user.timeoutUntil) > new Date()) { return socket.emit('chat_error', 'You are currently timed out and cannot send messages.'); } if (socket.username && msg) { try { const sender = await User.findOne({ username: socket.username }).select('pfp').lean(); if (!sender) return; const newMessage = new Message({ username: socket.username, message: msg }); await newMessage.save(); io.emit('chat_message', { ...newMessage.toObject(), pfp: sender.pfp }); } catch (err) { console.error("Error saving/sending chat message:", err); } }});
    socket.on('delete_message', async (messageId) => { try { const requester = await User.findById(socket.userId); const message = await Message.findById(messageId); if (!message) return; const isOwnMessage = message.username === socket.username; const fiveMinutes = 5 * 60 * 1000; const isWithinTime = Date.now() - message.timestamp.getTime() < fiveMinutes; if (requester.isAdmin || requester.isOwner || (isOwnMessage && isWithinTime)) { await Message.findByIdAndDelete(messageId); io.emit('message_deleted', messageId); } } catch (error) { console.error("Error deleting message:", error); }});
    socket.on('disconnect', async () => { if (socket.userId) { try { await User.findByIdAndUpdate(socket.userId, { online: false }); await broadcastOnlineUsers(); blackjackGames.delete(socket.userId); minesGames.delete(socket.userId); console.log(`User disconnected: ${socket.username}`); } catch (err) { console.error("Error during socket disconnect:", err); } }});
});
async function broadcastOnlineUsers() { try { const onlineUsers = await User.find({ online: true }).select('username coins pfp'); io.emit('online_users', onlineUsers); } catch(err) { console.error("Error broadcasting online users:", err); }};
setInterval(broadcastOnlineUsers, 5000);

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
server.listen(PORT, () => { console.log(`Server running on http://localhost:${PORT}`); });