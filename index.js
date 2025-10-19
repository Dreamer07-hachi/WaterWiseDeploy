import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import http from 'http';
import { WebSocketServer } from 'ws';
import path from 'path';
import { fileURLToPath } from 'url';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import passport from 'passport';
import GoogleStrategy from 'passport-google-oauth20';

dotenv.config();

const app = express();  
const port = 3000;
const saltRounds = 10;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set("view engine", "ejs");
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const activeConnections = new Map();

wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const orderId = url.searchParams.get('orderId');

    if (orderId) {
        console.log(`Client connected for order ${orderId}`);
        activeConnections.set(orderId, ws);

        ws.on('close', () => {
            console.log(`Client disconnected for order ${orderId}`);
            activeConnections.delete(orderId);
        });

        ws.on('error', (error) => {
            console.error('WebSocket error:', error);
            activeConnections.delete(orderId);
        });
    }
});

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(passport.initialize()); // Initializes Passport
app.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});
db.connect();

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) { // ⭐ Use Passport's built-in method
        return next();
    }
    res.redirect("/login");
};

app.get("/", (req, res) => {
  if (req.user) {
    res.redirect("/home");
  } else {
    res.render("prehome.ejs", { error: null, message: req.query.message });
  }
});

app.get("/prehome", (req, res) => {
    res.render("prehome.ejs", { error: null, message: req.query.message });
});

app.get("/register", (req, res) => {
  if (req.user) {
    res.redirect("/home");
  } else {
    res.render("register.ejs", { error: null, message: req.query.message });
  }
});

app.get("/detection", isAuthenticated, (req, res) => {
    res.render("detection.ejs", { 
        user: req.user, 
        message: req.query.message,
        error: req.query.error
    });
});

// This is new route to serve the dashboard page
app.get("/gotometer", isAuthenticated, (req, res) => {
     if (req.user) {
    res.redirect("/home");
  } else {
    res.render("dashboard.ejs", { error: null, message: req.query.message });
  }
});

app.get("/meter", (req, res) => {

    res.render("meter.ejs", { error: null, message: req.query.message });

});

app.get("/dashboard", isAuthenticated, (req, res) => {
    res.render("dashboard1.ejs", { error: null, message: req.query.message });
});

app.get("/conservation", isAuthenticated, (req, res) => {
    res.render("conservation.ejs", { 
        user: req.user, 
        message: req.query.message,
        error: req.query.error
    });
});

app.get("/login", (req, res) => {
  if (req.user) {
    res.redirect("/home");
  } else {
    res.render("login.ejs", { error: null, message: req.query.message });
  }
});

/*app.get("/home", (req, res) => {
  if (req.user) {
    res.render("home.ejs", { user: req.user });
  } else {
    res.redirect("/");
  }
});*/

app.post("/register", async (req, res) => {
  const { fullName, phoneNumber, password } = req.body;

  try {
    const checkResult = await db.query('SELECT * FROM users WHERE phone_number = $1', [phoneNumber]);
    if (checkResult.rows.length > 0) {
      return res.render("login.ejs", { error: "Phone number already registered. Please log in.", message: null });
    }
    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.error("Error hashing password:", err);
        return res.render("login.ejs", { error: "Registration failed. Please try again.", message: null });
      }
      const result = await db.query(
        'INSERT INTO users (full_name, phone_number, password_hash) VALUES ($1, $2, $3) RETURNING id, full_name, phone_number',
        [fullName, phoneNumber, hash]
      );
      console.log(`New user registered: ${result.rows[0].full_name}`);
      res.redirect("/?message=Registration successful! Please log in.");
    }); } catch (err) {
    console.error(err);
    res.render("login.ejs", { error: "An error occurred during registration.", message: null });
  }
});

app.post("/login", async (req, res, next) => { // ⭐ Add 'next'
    try {
        const result = await db.query('SELECT * FROM users WHERE phone_number = $1', [req.body.phoneNumber]);
        if (result.rows.length === 0) {
            return res.render("login.ejs", { error: "Invalid phone number or password.", message: null });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(req.body.password, user.password_hash);

        if (isMatch) {
            // ✅ Use Passport's built-in login function
            req.logIn(user, (err) => {
                if (err) return next(err);
                // Passport now handles the session and creates req.user
                return res.redirect("/home");
            });
        } else {
            res.render("login.ejs", { error: "Invalid phone number or password.", message: null });
        }
    } catch (err) {
        console.error(err);
        res.render("login.ejs", { error: "An error occurred during login.", message: null });
    }
});

app.get("/home", isAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;
        const deliveryMessage = req.query.message; 

        // I've added the two new queries for society data into your Promise.all call
        const [
            lastOrderResult,
            monthlyOrdersResult,
            trustedSuppliersResult,
            ordersToRateResult,
            userSocietyResult, // ⭐ NEW
            societyListResult   // ⭐ NEW
        ] = await Promise.all([
            db.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY order_time DESC LIMIT 1', [userId]),
            db.query('SELECT total_price FROM orders WHERE user_id = $1 AND EXTRACT(MONTH FROM order_time) = EXTRACT(MONTH FROM NOW()) AND EXTRACT(YEAR FROM order_time) = EXTRACT(YEAR FROM NOW())', [userId]),
            db.query(`SELECT COUNT(DISTINCT s.id) AS supplier_count FROM orders o JOIN tankers t ON o.tanker_id = t.id JOIN suppliers s ON t.supplier_id = s.id WHERE o.user_id = $1`, [userId]),
            db.query(`SELECT o.id, o.order_time, s.business_name FROM orders o JOIN tankers t ON o.tanker_id = t.id JOIN suppliers s ON t.supplier_id = s.id WHERE o.user_id = $1 AND o.order_status = 'Delivered' AND NOT EXISTS (SELECT 1 FROM ratings r WHERE r.order_id = o.id) ORDER BY o.order_time DESC`, [userId]),
            db.query('SELECT society_id FROM users WHERE id = $1', [userId]), // ⭐ NEW: Get user's society
            db.query(`SELECT id, society_name FROM societies WHERE verification_status = 'Approved' ORDER BY society_name`) // ⭐ NEW: Get list of all societies
        ]);

        const lastOrder = lastOrderResult.rows[0] || null;
        const totalSpentThisMonth = monthlyOrdersResult.rows.reduce((sum, order) => sum + parseFloat(order.total_price), 0);
        const trustedSuppliersCount = parseInt(trustedSuppliersResult.rows[0]?.supplier_count || 0);
        const ordersToRate = ordersToRateResult.rows;
        
        // ⭐ NEW: Process the new society data
        const userSocietyId = userSocietyResult.rows[0]?.society_id || null;
        const societies = societyListResult.rows;

        // Pass all the data to the home page
        res.render("home.ejs", {
            user: req.user,
            lastOrder,
            totalSpentThisMonth,
            trustedSuppliersCount,
            ordersToRate,
            deliveryMessage,
            userSocietyId, // ⭐ NEW
            societies      // ⭐ NEW
        });

    } catch (err) {
        console.error("Error fetching data for home page:", err);
        res.render("home.ejs", { 
            user: req.user, 
            ordersToRate: [],
            lastOrder: null,
            totalSpentThisMonth: 0,
            trustedSuppliersCount: 0,
            deliveryMessage: "Could not load dashboard data.",
            userSocietyId: null, // ⭐ NEW
            societies: []      // ⭐ NEW
        });
    }
});

app.post("/join-society", isAuthenticated, async (req, res) => {
    const { societyId } = req.body;
    const userId = req.user.id;
    try {
        await db.query('UPDATE users SET society_id = $1 WHERE id = $2', [societyId, userId]);
        res.redirect("/home");
    } catch (err) {
        console.error("Error joining society:", err);
        res.redirect("/home");
    }
});

app.get("/book-tanker", isAuthenticated, async (req, res) => {
    try {
        const query = `
            SELECT 
                t.id, t.capacity_litres, t.price_per_1000_litres, s.business_name,
                COALESCE(avg_ratings.avg_rating, 0) as average_rating,
                COALESCE(avg_ratings.rating_count, 0) as rating_count
            FROM tankers t
            JOIN suppliers s ON t.supplier_id = s.id
            LEFT JOIN (
                SELECT supplier_id, AVG(rating_value) as avg_rating, COUNT(rating_value) as rating_count
                FROM ratings
                GROUP BY supplier_id
            ) as avg_ratings ON s.id = avg_ratings.supplier_id
            WHERE s.verification_status = 'Approved' AND t.is_available = true
            ORDER BY average_rating DESC;
        `;
        const result = await db.query(query);
        const tankers = result.rows;
        res.render("book_tanker.ejs", { user: req.user, tankers: tankers });
    } catch (err) {
        console.error("Failed to fetch tankers:", err);
        res.redirect("/home");
    }
});

app.post("/confirm-order", isAuthenticated, async (req, res) => {
    const { tankerId } = req.body;
    try {
        const result = await db.query(
            `SELECT t.id, t.capacity_litres, t.price_per_1000_litres, s.business_name 
             FROM tankers t JOIN suppliers s ON t.supplier_id = s.id WHERE t.id = $1`,
            [tankerId]
        );
        if (result.rows.length > 0) {
            const tanker = result.rows[0];
            res.render("confirm-order.ejs", { user: req.user, tanker: tanker });
        } else {
            res.redirect("/book-tanker");
        }
    } catch (err) {
        console.error("Error fetching tanker for confirmation:", err);
        res.redirect("/book-tanker");
    }
});

/*app.post("/create-order", isAuthenticated, async (req, res) => {
    const { tankerId, deliveryAddress, totalPrice } = req.body;
    const userId = req.user.id;

    try {
        const result = await db.query(
            `INSERT INTO orders (user_id, tanker_id, delivery_address, total_price, order_status, payment_status) 
             VALUES ($1, $2, $3, $4, 'En-Route', 'Paid') RETURNING id`,
            [userId, tankerId, deliveryAddress, totalPrice]
        );
        
        const newOrderId = result.rows[0].id;
        res.redirect(`/order-success/${newOrderId}`);

    } catch (err) { 
        console.error("Error creating order:", err);
        res.redirect("/book-tanker");
    }
});*/

app.post("/create-order-razorpay", isAuthenticated, async (req, res) => {
    const { totalPrice } = req.body;
    const amountInPaise = Math.round(parseFloat(totalPrice) * 100);

    const options = {
        amount: amountInPaise,
        currency: "INR",
        receipt: `receipt_order_${new Date().getTime()}`,
    };

    try {
        const order = await razorpay.orders.create(options);
        if (!order) {
            return res.status(500).send("Error creating Razorpay order.");
        }
        res.json(order);
    } catch (err) {
        console.error("Razorpay order creation error:", err);
        res.status(500).send("Server error during payment initiation.");
    }
});

app.post("/payment-verification", isAuthenticated, async (req, res) => {
    const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
        tankerId,
        deliveryAddress,
        totalPrice
    } = req.body;
    
    const userId = req.user.id;
    const key_secret = process.env.RAZORPAY_KEY_SECRET;

    // Create a signature for verification
    const generated_signature = crypto
        .createHmac('sha256', key_secret)
        .update(razorpay_order_id + "|" + razorpay_payment_id)
        .digest('hex');

    // Securely compare the signatures
    if (generated_signature === razorpay_signature) {
        try {
            // If payment is verified, create the order in your database
            const result = await db.query(
                `INSERT INTO orders (user_id, tanker_id, delivery_address, total_price, order_status, payment_status, payment_id) 
                 VALUES ($1, $2, $3, $4, 'En-Route', 'Paid', $5) RETURNING id`,
                [userId, tankerId, deliveryAddress, totalPrice, razorpay_payment_id]
            );
            const newOrderId = result.rows[0].id;
            
            // Send success response to client to handle redirect
            res.json({ success: true, orderId: newOrderId });

        } catch (dbError) {
            console.error("Database error after payment verification:", dbError);
            res.status(500).json({ success: false, message: "Database error after payment." });
        }
    } else {
        res.status(400).json({ success: false, message: "Payment verification failed." });
    }
});


app.get("/order-success/:orderId", isAuthenticated, (req, res) => {
    res.render("order-success.ejs", { user: req.user, orderId: req.params.orderId });
});



app.post("/api/tanker/location", async (req, res) => {
    const { tankerId, latitude, longitude } = req.body;
    try {
        const locationString = `POINT(${longitude} ${latitude})`;
        await db.query(
            `UPDATE tankers SET current_location = ST_SetSRID(ST_GeomFromText($1), 4326) WHERE id = $2`,
            [locationString, tankerId]
        );
        
        const orderResult = await db.query(
            `SELECT id FROM orders WHERE tanker_id = $1 AND order_status = 'En-Route' LIMIT 1`,
            [tankerId]
        );
        
        if (orderResult.rows.length > 0) {
            const orderId = orderResult.rows[0].id.toString();
            const ws = activeConnections.get(orderId);
            if (ws && ws.readyState === 1) {
                ws.send(JSON.stringify({ latitude, longitude }));
            }
        }
        
        res.sendStatus(200);
    } catch (err) {
        console.error("Failed to update location:", err);
        res.sendStatus(500);
    }
});

app.get("/track-order/:orderId", isAuthenticated, async (req, res) => {
    try {
        const { orderId } = req.params;
        const query = `
            SELECT 
                o.id, 
                o.delivery_address, 
                s.business_name,
                ST_X(t.current_location::geometry) as lng, -- Extracts Longitude
                ST_Y(t.current_location::geometry) as lat  -- Extracts Latitude
             FROM orders o
             JOIN tankers t ON o.tanker_id = t.id
             JOIN suppliers s ON t.supplier_id = s.id
             WHERE o.id = $1 AND o.user_id = $2
        `;

        const result = await db.query(query, [orderId, req.user.id]);
        
        if (result.rows.length > 0) {
            const order = result.rows[0];
            const initialCoords = order.lat && order.lng ? { lat: order.lat, lng: order.lng } : null;
            
            res.render("track-order.ejs", { user: req.user, order, initialCoords });
        } else {
            res.status(404).send("Order not found or you do not have permission to view it.");
        }
    } catch (err) {
        console.error("Error fetching order for tracking:", err);
        res.redirect("/home");
    }
});

app.get("/driver-view/:orderId", async (req, res) => {
    const { orderId } = req.params;

    // This query now JOINS the tables to get the supplier's name
    const query = `
        SELECT
            o.id,
            o.tanker_id,
            s.business_name
        FROM orders AS o
        JOIN tankers AS t ON o.tanker_id = t.id
        JOIN suppliers AS s ON t.supplier_id = s.id
        WHERE o.id = $1
    `;

    try {
        const result = await db.query(query, [orderId]);

        if (result.rows.length > 0) {
            // FIX: Pass the data as 'supplier'. 
            // I'm also passing it as 'order' in case you need other order details.
            res.render("driver-view.ejs", {
                supplier: result.rows[0],
                order: result.rows[0]
            });
        } else {
            res.status(404).send("Order not found");
        }
    } catch (err) {
        console.error("Error fetching driver view data:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/order-delivered", async (req, res) => {
    const { orderId } = req.body;
    try {
        await db.query(`UPDATE orders SET order_status = 'Delivered' WHERE id = $1`, [orderId]);
        const ws = activeConnections.get(orderId.toString());

        if (ws && ws.readyState === 1) {
            console.log(`[Server] Found connection for Order #${orderId}. Sending 'delivered' message.`);
            ws.send(JSON.stringify({ type: 'delivered' }));
            ws.close();
        } else {
            console.log(`[Server] Could NOT find active connection for Order #${orderId}.`);
        }

        res.send(`<div style="font-family: sans-serif; text-align: center; margin-top: 5rem;"><h1>Order #${orderId} marked as Delivered!</h1><p>You can now close this window.</p></div>`);
    } catch (err) {
        console.error("Error marking order as delivered:", err);
        res.status(500).send("Failed to update order status.");
    }
});

app.get("/rate-order/:orderId", isAuthenticated, async (req, res) => {
    const { orderId } = req.params;
    try {
        const result = await db.query(
            `SELECT o.id, s.id as supplier_id, s.business_name FROM orders o
             JOIN tankers t ON o.tanker_id = t.id
             JOIN suppliers s ON t.supplier_id = s.id
             WHERE o.id = $1 AND o.user_id = $2 AND o.order_status = 'Delivered'`,
            [orderId, req.user.id]
        );
        if (result.rows.length > 0) {
            res.render("rate-order.ejs", { user: req.user, order: result.rows[0] });
        } else {
            res.status(404).send("This order is not available for rating.");
        }
    } catch (err) {
        console.error("Error fetching order for rating:", err);
        res.redirect("/home");
    }
});

app.get("/order-history", isAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;
        const query = `SELECT 
                o.id,
                o.order_time,
                o.delivery_address,
                o.total_price,
                o.order_status,
                s.business_name
            FROM orders o
            JOIN tankers t ON o.tanker_id = t.id
            JOIN suppliers s ON t.supplier_id = s.id
            WHERE o.user_id = $1
            ORDER BY o.order_time DESC;`;
        const result = await db.query(query, [userId]);
        
        res.render("order-history.ejs", {
            user: req.user,
            orders: result.rows
        });

    } catch (err) {
        console.error("Error fetching order history:", err);
        res.redirect("/home");
    }
});

app.get("/profile", isAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;
        const result = await db.query('SELECT full_name, phone_number FROM users WHERE id = $1', [userId]);
        
        if (result.rows.length > 0) {
            res.render("profile.ejs", {
                user: req.user,
                userData: result.rows[0],
                message: req.query.message,
                error: req.query.error
            });
        } else {
            res.redirect("/home");
        }
    } catch (err) {
        console.error("Error fetching user profile:", err);
        res.redirect("/home");
    }
});

app.post("/update-profile", isAuthenticated, async (req, res) => {
    const { fullName, phoneNumber, newPassword, confirmPassword } = req.body;
    const userId = req.user.id;
    if (newPassword && newPassword !== confirmPassword) {
        return res.redirect("/profile?error=" + encodeURIComponent("New passwords do not match."));
    }

    try {
        const updateUserQuery = 'UPDATE users SET full_name = $1, phone_number = $2 WHERE id = $3 RETURNING full_name, phone_number';
        const updatedUser = await db.query(updateUserQuery, [fullName, phoneNumber, userId]);

        req.user.name = updatedUser.rows[0].full_name;
        req.user.phone = updatedUser.rows[0].phone_number;

        if (newPassword) {
            const hash = await bcrypt.hash(newPassword, saltRounds);
            await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, userId]);
        }

        res.redirect("/profile?message=" + encodeURIComponent("Profile updated successfully!"));

    } catch (err) {
        console.error("Error updating profile:", err);
        if (err.code === '23505') { 
            return res.redirect("/profile?error=" + encodeURIComponent("This phone number is already in use by another account."));
        }
        res.redirect("/profile?error=" + encodeURIComponent("An error occurred while updating your profile."));
    }
});

app.post("/submit-rating", isAuthenticated, async (req, res) => {
    const { orderId, supplierId, ratingValue, reviewText } = req.body;
    try {
        await db.query(
            `INSERT INTO ratings (order_id, user_id, supplier_id, rating_value, review_text)
             VALUES ($1, $2, $3, $4, $5)`,
            [orderId, req.user.id, supplierId, ratingValue, reviewText]
        );
        res.redirect("/home");
    } catch (err) {
        console.error("Error submitting rating:", err);
        res.redirect(`/rate-order/${orderId}`);
    }
});

app.get('/dashboard', async (req, res) => {
    if (!req.userId) {
        return res.redirect('/login');
    }

    try {
        const userId = req.userId;
        const [
            lastOrderResult,
            monthlyOrdersResult,
            trustedSuppliersResult,
            ordersToRateResult
        ] = await Promise.all([
            db.query('SELECT * FROM orders WHERE user_id = ? ORDER BY order_time DESC LIMIT 1', [userId]),
            db.query('SELECT cost FROM orders WHERE user_id = ? AND MONTH(order_time) = MONTH(CURDATE()) AND YEAR(order_time) = YEAR(CURDATE())', [userId]),
            db.query('SELECT COUNT(DISTINCT supplier_id) AS supplierCount FROM orders WHERE user_id = ?', [userId]),

            db.query(`
                SELECT o.id, o.order_time, s.business_name 
                FROM orders o
                JOIN suppliers s ON o.supplier_id = s.id
                WHERE o.user_id = ? AND o.status = 'delivered' AND o.rating IS NULL
                ORDER BY o.order_time DESC
            `, [userId])
        ]);

        const lastOrder = lastOrderResult.rows[0] || null;
        
        const totalSpentThisMonth = monthlyOrdersResult.rows.reduce((sum, order) => sum + parseFloat(order.cost), 0);
        
        const trustedSuppliersCount = trustedSuppliersResult.rows[0]?.suppliercount || 0;
        
        const ordersToRate = ordersToRateResult.rows;

        res.render('dashboard', {
            lastOrder: lastOrder,
            totalSpentThisMonth: totalSpentThisMonth,
            trustedSuppliersCount: trustedSuppliersCount,
            ordersToRate: ordersToRate,
            deliveryMessage: req.flash('deliveryMessage') 
        });

    } catch (err) {
        console.error("Error fetching dashboard data:", err);
        res.status(500).send("Error loading dashboard.");
    }
});

// A more standard way to handle logout
app.get("/logout", (req, res, next) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

app.post('/api/consumption', async (req, res) => {
  const { user_id, consumption_liters } = req.body;
  try {
    await db.query(
      'INSERT INTO water_consumption (user_id, consumption_liters, timestamp) VALUES ($1, $2, NOW())',
      [user_id, consumption_liters]
    );
    res.status(201).send('Consumption logged successfully.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error.');
  }
});

async function detectLeaks() {
  const costPerLiter = 0.05;

  try {
    // Check if any users have logged data
    const usersResult = await db.query('SELECT DISTINCT user_id FROM water_consumption');
    const userIds = usersResult.rows.map(row => row.user_id);
    console.log(`[Leak Detection] Running check for ${userIds.length} user(s).`);

    for (const userId of userIds) {
      console.log(`[Leak Detection] Checking user ID: ${userId}`);

      // Rule 1: Continuous Low Flow
      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const continuousLeakThreshold = 0.5;
      const continuousLeakDuration = 4;

      const continuousFlowResult = await db.query(
        `SELECT COUNT(*) FROM water_consumption
         WHERE user_id = $1 AND timestamp > $2 AND consumption_liters > $3`,
        [userId, oneHourAgo, continuousLeakThreshold]
      );
     
      const continuousCount = continuousFlowResult.rows[0].count;
      console.log(`[Leak Detection] User ${userId}: Found ${continuousCount} data points > ${continuousLeakThreshold}L in the last hour.`);
     
      if (continuousCount >= continuousLeakDuration) {
        console.log(`[ALERT] Continuous flow leak detected for user: ${userId}`);
        const anomalousConsumption = continuousCount * continuousLeakThreshold;
        const estimatedCost = anomalousConsumption * costPerLiter;
        await db.query(
          'INSERT INTO potential_leaks (user_id, anomalous_consumption_liters, leak_type, cost_inr) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
          [userId, anomalousConsumption, 'Continuous Flow', estimatedCost]
        );
      }

      // Rule 2: High Overnight Consumption
      const overnightThreshold = 50;
      const startOfDay = new Date();
      startOfDay.setHours(0, 0, 0, 0);
      const endOfDay = new Date();
      endOfDay.setHours(23, 59, 59, 999);
     
      const overnightResult = await db.query(
        `SELECT SUM(consumption_liters) as total_consumption FROM water_consumption
         WHERE user_id = $1 AND timestamp BETWEEN $2 AND $3`,
        [userId, startOfDay, endOfDay]
      );
     
      const totalOvernight = overnightResult.rows[0].total_consumption || 0;
      console.log(`[Leak Detection] User ${userId}: Total consumption today is ${totalOvernight.toFixed(2)}L.`);

      if (totalOvernight > overnightThreshold) {
        console.log(`[ALERT] High overnight usage detected for user: ${userId}`);
        const anomalousConsumption = totalOvernight;
        const estimatedCost = anomalousConsumption * costPerLiter;
        await db.query(
          'INSERT INTO potential_leaks (user_id, anomalous_consumption_liters, leak_type, cost_inr) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
          [userId, anomalousConsumption, 'High Overnight Usage', estimatedCost]
        );
      }
    }
  } catch (err) {
    console.error('Advanced leak detection failed:', err);
  }
}

app.get('/api/leaks', async (req, res) => {
  const userId = req.query.user_id;
  if (!userId) {
    return res.status(400).send('User ID is required.');
  }
  try {
    const { rows } = await db.query(
      'SELECT * FROM potential_leaks WHERE user_id = $1 ORDER BY detection_timestamp DESC',
      [userId]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error.');
  }
});

app.get('/api/consumption_data', async (req, res) => {
    const userId = req.query.user_id;
    if (!userId) {
        return res.status(400).send('User ID is required.');
    }
    try {
        const { rows } = await db.query(
            'SELECT timestamp, consumption_liters FROM water_consumption WHERE user_id = $1 ORDER BY timestamp ASC LIMIT 100',
            [userId]
        );
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});
setInterval(detectLeaks, 3600000);

app.get("/register-supplier", (req, res) => {
    // Pass the user session if it exists for the header, otherwise pass null
    const user = req.user || null;
    res.render("supplier-register.ejs", { 
        user: user,
        error: null,
        message: null
    });
});

app.post("/register-supplier", async (req, res) => {
    const {
        businessName, contactPerson, phoneNumber, password,
        // Add the tanker details from the form
        vehicleNumber, capacity, price
    } = req.body;

    // Add a quick check for password
    if (!password) {
        return res.render("supplier-register.ejs", { user: req.user || null, error: "Password is required.", message: null });
    }

    const client = await db.connect();
    try {
        await client.query('BEGIN'); // Start a transaction

        const checkResult = await client.query('SELECT * FROM suppliers WHERE phone_number = $1', [phoneNumber]);
        if (checkResult.rows.length > 0) {
            return res.render("supplier-register.ejs", { user: req.user || null, error: "This phone number is already registered.", message: null });
        }

        // Hash the password from the form
        const hash = await bcrypt.hash(password, saltRounds);

        // Insert the new supplier, including the hashed password
        const supplierResult = await client.query(
            `INSERT INTO suppliers (business_name, contact_person, phone_number, password_hash)
             VALUES ($1, $2, $3, $4) RETURNING id`,
            [businessName, contactPerson, phoneNumber, hash] // <-- Pass the hash to the query
        );
        const newSupplierId = supplierResult.rows[0].id;
        
        // This part is now re-enabled to save the tanker details
        await client.query(
            `INSERT INTO tankers (supplier_id, vehicle_number, capacity_litres, price_per_1000_litres)
             VALUES ($1, $2, $3, $4)`,
            [newSupplierId, vehicleNumber, parseInt(capacity), parseFloat(price)]
        );

        await client.query('COMMIT'); // Commit the transaction
        
        res.render("supplier-register.ejs", { user: req.user || null, error: null, message: "Application submitted successfully! Our team will review it and you will be able to login once approved." });

    } catch (err) {
        await client.query('ROLLBACK'); 
        console.error("Error during supplier registration:", err);
        res.render("supplier-register.ejs", { user: req.user || null, error: "An error occurred during registration.", message: null });
    } finally {
        client.release();
    }
});

app.get("/login-supplier", (req, res) => {
    res.render("supplier-login.ejs", { error: null });
});

app.post("/login-supplier", async (req, res) => {
    const { phoneNumber, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM suppliers WHERE phone_number = $1', [phoneNumber]);
        if (result.rows.length === 0) {
            return res.render("supplier-login.ejs", { error: "Invalid phone number or password." });
        }
        
        const supplier = result.rows[0];
        
        // Ensure supplier is approved before allowing login
        if (supplier.verification_status !== 'Approved') {
            return res.render("supplier-login.ejs", { error: "Your account is still pending approval by an admin." });
        }

        const isMatch = await bcrypt.compare(password, supplier.password_hash);
        if (isMatch) {
            // Create a separate session for the supplier
            req.session.supplier = {
                id: supplier.id,
                businessName: supplier.business_name,
            };
            res.redirect("/supplier/dashboard");
        } else {
            res.render("supplier-login.ejs", { error: "Invalid phone number or password." });
        }
    } catch (err) {
        console.error("Supplier login error:", err);
        res.render("supplier-login.ejs", { error: "An error occurred. Please try again." });
    }
});

const isSupplierAuthenticated = (req, res, next) => {
    if (req.session.supplier) {
        return next();
    }
    res.redirect("/login-supplier");
};

// --- Routes for Supplier Dashboard ---
app.get("/supplier/dashboard", isSupplierAuthenticated, async (req, res) => {
    try {
        const supplierId = req.session.supplier.id;
        const query = `
            SELECT 
                o.id, o.order_time, o.delivery_address, o.total_price, o.order_status,
                u.full_name
            FROM orders o
            JOIN users u ON o.user_id = u.id
            JOIN tankers t ON o.tanker_id = t.id
            WHERE t.supplier_id = $1
            ORDER BY o.order_time DESC;
        `;
        const result = await db.query(query, [supplierId]);
        
        res.render("supplier-dashboard.ejs", {
            supplier: req.session.supplier,
            orders: result.rows
        });
    } catch (err) {
        console.error("Error fetching supplier orders:", err);
        res.status(500).send("Failed to load dashboard.");
    }
});

app.get("/logout-supplier", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Failed to destroy supplier session:", err);
        }
        res.redirect("/login-supplier");
    });
});

const CUBIC_FEET_TO_METERS = 0.0283168; // The conversion factor
// API endpoint to save a new meter reading
app.post("/api/readings", isAuthenticated, async (req, res) => {
    let { readingValue, unit } = req.body;
    if (!readingValue || !unit) return res.status(400).json({ error: "Reading value and unit are required." });
    if (unit === 'cubic_feet') {
        readingValue = readingValue * 0.0283168;
    }
    try {
        const sql = 'INSERT INTO readings (user_id, reading_value) VALUES ($1, $2) RETURNING *';
        const result = await db.query(sql, [req.user.id, readingValue]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error("Error saving reading:", err);
        res.status(500).json({ error: "Failed to save reading." });
    }
});

// FINAL, DEFINITIVE GET ENDPOINT
app.get("/api/readings", isAuthenticated, async (req, res) => {
  try {
    const userId = req.user.id;
    const { range, startDate: customStartDate, endDate: customEndDate } = req.query;

    let chartStartDate = new Date();
    let fetchEndDate = new Date();

    if (customStartDate && customEndDate) {
      chartStartDate = new Date(customStartDate);
      fetchEndDate = new Date(customEndDate);
    } else {
      const effectiveRange = range || 'week';
      if (effectiveRange === 'month') { chartStartDate.setDate(chartStartDate.getDate() - 29); } 
      else if (effectiveRange === 'year') { chartStartDate.setFullYear(chartStartDate.getFullYear() - 1); } 
      else { chartStartDate.setDate(chartStartDate.getDate() - 6); }
    }
    
    chartStartDate.setHours(0, 0, 0, 0);
    
    // --- START OF FIX ---
    // Make sure the end date includes the entire day
    fetchEndDate.setHours(23, 59, 59, 999);
    
    // The start date for fetching needs to be one day before the chart's start
    const fetchStartDate = new Date(chartStartDate);
    fetchStartDate.setDate(fetchStartDate.getDate() - 1);
    // --- END OF FIX ---

    const sql = `
      SELECT reading_value, created_at 
      FROM readings 
      WHERE user_id = $1 AND created_at >= $2 AND created_at <= $3
      ORDER BY created_at ASC
    `;
    const dbResult = await db.query(sql, [userId, fetchStartDate, fetchEndDate]);

    // ... The rest of the calculation logic remains exactly the same
    if (dbResult.rows.length < 2) return res.json([]);
    const consumptionByEntry = [];
    for (let i = 1; i < dbResult.rows.length; i++) {
        const consumption = (dbResult.rows[i].reading_value - dbResult.rows[i-1].reading_value);
        const date = new Date(dbResult.rows[i].created_at).toISOString().split('T')[0];
        consumptionByEntry.push({ date, consumption });
    }
    const dailyTotals = {};
    consumptionByEntry.forEach(entry => {
        dailyTotals[entry.date] = (dailyTotals[entry.date] || 0) + entry.consumption;
    });
    const allCalculatedData = Object.keys(dailyTotals).map(date => ({
        date: date,
        consumption: parseFloat(dailyTotals[date].toFixed(2))
    }));
    const finalResult = allCalculatedData.filter(item => new Date(item.date) >= chartStartDate);
    res.json(finalResult);

  } catch (err) {
    console.error("Error fetching consumption data:", err);
    res.status(500).json({ error: "Failed to fetch data." });
  }
});


// API endpoint for gauge chart data
app.get("/api/gauge", isAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;
        const goalResult = await db.query('SELECT monthly_goal FROM users WHERE id = $1', [userId]);
        const goal = goalResult.rows[0]?.monthly_goal || 5000;

        const consumptionSql = `
            SELECT SUM(consumption) as "currentUsage" FROM (
                SELECT (last_reading - LAG(last_reading, 1) OVER (ORDER BY reading_day))::numeric(14, 2) AS consumption
                FROM (
                    SELECT DATE_TRUNC('day', created_at)::date AS reading_day, MAX(reading_value) as last_reading
                    FROM readings
                    WHERE user_id = $1 AND created_at >= DATE_TRUNC('month', NOW())
                    GROUP BY reading_day ORDER BY reading_day ASC
                ) as daily_readings
            ) as consumption_calc;`;
        const consumptionResult = await db.query(consumptionSql, [userId]);
        const currentUsage = consumptionResult.rows[0]?.currentUsage || 0;
        const monthName = new Date().toLocaleString('en-IN', { month: 'long' });

        res.json({
            month: monthName,
            currentUsage: parseFloat(currentUsage),
            goal: parseFloat(goal)
        });
    } catch (err) {
        console.error("Error fetching gauge data:", err);
        res.status(500).json({ error: "Failed to fetch gauge data." });
    }
});

// A hardcoded list of water-saving tips.
const waterSavingTips = [
    "Fix leaky faucets and toilets immediately. A small drip can waste gallons of water every day.",
    "Install water-efficient showerheads and tap aerators to reduce water flow without sacrificing pressure.",
    "Take shorter showers. Aim for 5 minutes or less to save a significant amount of water.",
    "Only run your washing machine and dishwasher with full loads to maximize water efficiency.",
    "Use a broom instead of a hose to clean driveways and sidewalks.",
    "Collect rainwater in a barrel to use for watering your plants and garden.",
    "Turn off the tap while brushing your teeth or shaving."
];

// New API endpoint to generate a consumption report
app.get("/api/report", isAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;
        const calculateDailyConsumption = (rows) => {
            if (rows.length < 2) return [];
            const dailyTotals = {};
            for (let i = 1; i < rows.length; i++) {
                const consumption = (parseFloat(rows[i].reading_value) - parseFloat(rows[i-1].reading_value));
                const date = new Date(rows[i].created_at).toISOString().split('T')[0];
                dailyTotals[date] = (dailyTotals[date] || 0) + consumption;
            }
            return Object.keys(dailyTotals).map(date => ({ date, consumption: dailyTotals[date] }));
        };
        
        const thirtyDaysData = await db.query(
            `SELECT reading_value, created_at FROM readings WHERE user_id = $1 AND created_at >= NOW() - INTERVAL '30 days' ORDER BY created_at ASC`,
            [userId]
        );
        
        const dailyConsumption30 = calculateDailyConsumption(thirtyDaysData.rows);
        if (dailyConsumption30.length === 0) {
            return res.json({ summary: "Not enough data to generate a report yet." });
        }
        
        const consumptionValues30 = dailyConsumption30.map(d => d.consumption);
        const average30 = consumptionValues30.reduce((a, b) => a + b, 0) / consumptionValues30.length;
        const dailyConsumption7 = dailyConsumption30.slice(-7);
        const consumptionValues7 = dailyConsumption7.map(d => d.consumption);
        const average7 = consumptionValues7.length > 0 ? consumptionValues7.reduce((a, b) => a + b, 0) / consumptionValues7.length : 0;
        const trend = ((average7 / average30) - 1) * 100;
        
        let highestDay = dailyConsumption30.reduce((max, day) => day.consumption > max.consumption ? day : max, dailyConsumption30[0]);
        
        const waterSavingTips = [ "Fix leaky faucets and toilets immediately.", "Install water-efficient showerheads.", "Take shorter showers." ];
        
        res.json({
            average7: average7.toFixed(2),
            average30: average30.toFixed(2),
            trend: trend.toFixed(1),
            highestDayDate: highestDay.date,
            highestDayConsumption: highestDay.consumption.toFixed(2),
            tips: waterSavingTips.sort(() => 0.5 - Math.random()).slice(0, 2)
        });
    } catch (err) {
        console.error("Error generating report:", err);
        res.status(500).json({ error: "Failed to generate report." });
    }
});

const isSocietyAuthenticated = (req, res, next) => {
    if (req.session.society) {
        return next();
    }
    res.redirect("/society/login");
};

// ⭐ NEW: Society Registration Routes
app.get("/society/register", (req, res) => {
    res.render("society-register.ejs", { error: null, message: null });
});

app.post("/society/register", async (req, res) => {
    const { societyName, address, chairmanName, chairmanPhone, password } = req.body;
    try {
        const checkResult = await db.query('SELECT * FROM societies WHERE chairman_phone = $1', [chairmanPhone]);
        if (checkResult.rows.length > 0) {
            return res.render("society-register.ejs", { error: "This phone number is already registered to a society.", message: null });
        }
        const hash = await bcrypt.hash(password, saltRounds);
        await db.query(
            'INSERT INTO societies (society_name, address, chairman_name, chairman_phone, password_hash) VALUES ($1, $2, $3, $4, $5)',
            [societyName, address, chairmanName, chairmanPhone, hash]
        );
        res.render("society-login.ejs", { error: null, message: "Registration successful! Please log in." });
    } catch (err) {
        console.error("Error during society registration:", err);
        res.render("society-register.ejs", { error: "An error occurred during registration.", message: null });
    }
});

// ⭐ NEW: Society Login Routes
app.get("/society/login", (req, res) => {
    res.render("society-login.ejs", { error: null, message: null });
});


// ✅ THIS IS THE CORRECTED SOCIETY LOGIN ROUTE
app.post("/society/login", async (req, res) => {
    const { chairmanPhone, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM societies WHERE chairman_phone = $1', [chairmanPhone]);
        if (result.rows.length === 0) {
            return res.render("society-login.ejs", { error: "Invalid phone number or password.", message: null });
        }

        const society = result.rows[0];
        const isMatch = await bcrypt.compare(password, society.password_hash);

        if (isMatch) {
            // Create a session for the logged-in society chairman
            req.session.society = {
                id: society.id,
                society_name: society.society_name,
                chairman_name: society.chairman_name
            };
            // Redirect to the dashboard upon successful login
            res.redirect("/society/dashboard");
        } else {
            res.render("society-login.ejs", { error: "Invalid phone number or password.", message: null });
        }
    } catch (err) {
        console.error("Error during society login:", err);
        res.render("society-login.ejs", { error: "An error occurred. Please try again.", message: null });
    }
});


// Main dashboard route
app.get("/society/dashboard", isSocietyAuthenticated, async (req, res) => {
    try {
        const societyId = req.session.society.id;

        // Query to get all necessary stats for the dashboard
        const statsQuery = `
            SELECT
                (SELECT COUNT(*) FROM users WHERE society_id = $1) as resident_count,
                (SELECT COALESCE(SUM(t.capacity_litres), 0) FROM orders o
                 JOIN tankers t ON o.tanker_id = t.id
                 JOIN users u ON o.user_id = u.id
                 WHERE u.society_id = $1 
                 AND EXTRACT(MONTH FROM o.order_time) = EXTRACT(MONTH FROM NOW())
                 AND EXTRACT(YEAR FROM o.order_time) = EXTRACT(YEAR FROM NOW())) as total_consumption_litres,
                (SELECT COUNT(*) FROM orders o -- This is a placeholder for actual bulk orders
                 JOIN users u ON o.user_id = u.id
                 WHERE u.society_id = $1
                 AND EXTRACT(MONTH FROM o.order_time) = EXTRACT(MONTH FROM NOW())
                 AND EXTRACT(YEAR FROM o.order_time) = EXTRACT(YEAR FROM NOW())) as bulk_orders_count;
        `;

        const statsResult = await db.query(statsQuery, [societyId]);

        res.render("society-dashboard.ejs", {
            society: req.session.society,
            stats: statsResult.rows[0]
        });

    } catch (err) {
        console.error("Error fetching society dashboard data:", err);
        // Render with empty stats on error
        res.render("society-dashboard.ejs", {
            society: req.session.society,
            stats: { resident_count: 0, total_consumption_litres: 0, bulk_orders_count: 0 }
        });
    }
});

// Logout route for society
app.get("/society/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Failed to destroy society session:", err);
            return res.redirect("/society/dashboard");
        }
        res.redirect("/");
    });
});

// Placeholder for sending a notice (we can build this out later)
app.post("/society/send-notice", isSocietyAuthenticated, (req, res) => {
    const { noticeMessage } = req.body;
    console.log(`Notice from Society #${req.session.society.id}: "${noticeMessage}"`);
    // In a real app, you would save this to a 'notices' table and notify users.
    res.redirect("/society/dashboard");
});



// ... (db.connect() is not needed with pg.Pool)

// ... (existing razorpay setup)

// ⭐ NEW: Passport Google OAuth2.0 Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // 1. Check if user already exists with this Google ID
        const checkResult = await db.query('SELECT * FROM users WHERE google_id = $1', [profile.id]);

        if (checkResult.rows.length > 0) {
            // User exists, log them in
            return done(null, checkResult.rows[0]);
        } else {
            // 2. User does not exist, create a new user
            const newUser = await db.query(
                `INSERT INTO users (full_name, google_id) VALUES ($1, $2) RETURNING *`,
                [profile.displayName, profile.id]
            );
            return done(null, newUser.rows[0]);
        }
    } catch (err) {
        return done(err, null);
    }
}));


// Used to store user info in the session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// In index.js, find and replace this entire function

passport.deserializeUser(async (id, done) => {
    try {
        const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
        if (result.rows.length > 0) {
            const userFromDb = result.rows[0];
            
            // This is the user object that becomes req.user on every request
            const userProfile = {
                id: userFromDb.id,
                name: userFromDb.full_name,
                phone: userFromDb.phone_number,
                googleId: userFromDb.google_id // ⭐ ADD THIS LINE
            };
            done(null, userProfile);
        } else {
            done(null, false); // User not found
        }
    } catch (err) {
        done(err);
    }
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

// ⭐ NEW: Callback route that Google redirects to
app.get('/auth/google/callback', 
    passport.authenticate('google', { 
        successRedirect: '/home',   // If login is successful, go to /home
        failureRedirect: '/login'   // If it fails, go back to /login
    })
);

app.get("/api/recent-readings", isAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;
        const sql = `
            SELECT reading_value, created_at 
            FROM readings 
            WHERE user_id = $1 
            ORDER BY created_at DESC 
            LIMIT 5
        `;
        const result = await db.query(sql, [userId]);
        res.json(result.rows);
    } catch (err) {
        console.error("Error fetching recent readings:", err);
        res.status(500).json({ error: "Failed to fetch recent readings." });
    }
});

const link="http://localhost:3000/"
app.listen(port, () => {
  console.log(`Server running on port ${link}`);
});


