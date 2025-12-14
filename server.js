const express = require('express');
const pg = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');



dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(cors({
    origin: [
    'http://localhost:3001',
    'http://127.0.0.1:5500',
    'https://deji985.github.io'
  ],
  credentials: true
}));


const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.on('connect',()=>{
    console.log('Connected to the database');
})

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = decoded;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.type !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
};



app.get('/api/profile', verifyToken, async (req, res) => {
    const table = req.user.type === 'admin' ? 'admins' : 'users';
    try {
        const result = await pool.query(`SELECT id, email, created_at FROM ${table} WHERE id = $1`, [req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/profile', verifyToken, async (req, res) => {
    const { email, password } = req.body;
    const table = req.user.type === 'admin' ? 'admins' : 'users';
    let query = `UPDATE ${table} SET `;
    const values = [];
    let index = 1;

    if (email) {
        query += `email = $${index}, `;
        values.push(email);
        index++;
    }
    if (password) {
        const hashed = await bcrypt.hash(password, 10);
        query += `password = $${index}, `;
        values.push(hashed);
        index++;
    }

    if (values.length === 0) return res.status(400).json({ error: 'No updates provided' });

    query = query.slice(0, -2) + ` WHERE id = $${index} RETURNING email`;
    values.push(req.user.id);

    try {
        const result = await pool.query(query, values);
        res.json({ success: true, message: 'Profile updated', email: result.rows[0].email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/profile', verifyToken, async (req, res) => {
    const table = req.user.type === 'admin' ? 'admins' : 'users';
    try {
        await pool.query(`DELETE FROM ${table} WHERE id = $1`, [req.user.id]);
        res.json({ success: true, message: 'Account deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

app.post('/api/register/user', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    const hashed = await bcrypt.hash(password, 10);
    try {
        await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashed]);
        res.status(201).json({ success: true, message: 'User registered successfully' });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'This email is already registered' });
        }
        console.error('User registration error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/register/admin', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    const hashed = await bcrypt.hash(password, 10);
    try {
        await pool.query('INSERT INTO admins (email, password) VALUES ($1, $2)', [email, hashed]);
        res.status(201).json({ success: true, message: 'Admin registered successfully' });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'This email is already registered as admin' });
        }
        console.error('Admin registration error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login/user', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0 || !await bcrypt.compare(password, result.rows[0].password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: result.rows[0].id, type: 'user' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/login/admin', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
        if (result.rows.length === 0 || !await bcrypt.compare(password, result.rows[0].password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: result.rows[0].id, type: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/api/menu', async (req, res) => {
    const result = await pool.query('SELECT * FROM menu_items');
    res.json(result.rows);
});

app.post('/api/menu', verifyToken, isAdmin, async (req, res) => {
    const { name, description, price, image_url } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO menu_items (name, description, price, image_url) VALUES ($1, $2, $3, $4) RETURNING *',
            [name, description, price, image_url]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Failed to add item' });
    }
});

app.post('/api/orders', verifyToken, async (req, res) => {
    const { items, total_price } = req.body;
    if (!items || !Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'No items provided' });
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const orderRes = await client.query(
            'INSERT INTO orders (user_id, total_price) VALUES ($1, $2) RETURNING *',
            [req.user.id, total_price]
        );
        const orderId = orderRes.rows[0].id;
        const insertPromises = items.map(it => client.query(
            'INSERT INTO order_items (order_id, menu_item_id, quantity, price) VALUES ($1, $2, $3, $4)',
            [orderId, it.menu_item_id, it.quantity, it.price]
        ));
        await Promise.all(insertPromises);
        await client.query('COMMIT');
        res.status(201).json({ success: true, order: orderRes.rows[0] });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Order creation error:', err);
        res.status(500).json({ error: 'Failed to create order' });
    } finally {
        client.release();
    }
});

app.get('/api/orders', verifyToken, async (req, res) => {
    try {
        if (req.user.type === 'admin') {
            const result = await pool.query(
                `SELECT o.*, COALESCE(json_agg(json_build_object('id', oi.id, 'menu_item_id', oi.menu_item_id, 'menu_item_name', mi.name, 'quantity', oi.quantity, 'price', oi.price)) FILTER (WHERE oi.id IS NOT NULL), '[]') as items
                 FROM orders o
                 LEFT JOIN order_items oi ON oi.order_id = o.id
                 LEFT JOIN menu_items mi ON mi.id = oi.menu_item_id
                 GROUP BY o.id
                 ORDER BY o.created_at DESC`
            );
            return res.json(result.rows);
        }
        const result = await pool.query(
            `SELECT o.*, COALESCE(json_agg(json_build_object('id', oi.id, 'menu_item_id', oi.menu_item_id, 'menu_item_name', mi.name, 'quantity', oi.quantity, 'price', oi.price)) FILTER (WHERE oi.id IS NOT NULL), '[]') as items
             FROM orders o
             LEFT JOIN order_items oi ON oi.order_id = o.id
             LEFT JOIN menu_items mi ON mi.id = oi.menu_item_id
             WHERE o.user_id = $1
             GROUP BY o.id
             ORDER BY o.created_at DESC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Get orders error:', err);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

app.put('/api/orders/:id/status', verifyToken, isAdmin, async (req, res) => {
    const { status } = req.body;
    try {
        const result = await pool.query('UPDATE orders SET status = $1 WHERE id = $2 RETURNING *', [status, req.params.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Update order status error:', err);
        res.status(500).json({ error: 'Failed to update order status' });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

process.on('unhandledRejection', err => {
    console.error('Unhandled Rejection:', err);
});