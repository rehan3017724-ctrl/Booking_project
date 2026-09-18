require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const path = require('path');

const {
    requireLogin,
    requireAdmin,
    requireOwner
} = require('./middleware/auth');

const app = express();

const PORT = process.env.PORT || 3000;

/* =========================
   EXPRESS CONFIGURATION
========================= */

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));

/* =========================
   SESSION
========================= */

app.use(
    session({
        secret: process.env.SESSION_SECRET || 'secret',
        resave: false,
        saveUninitialized: false
    })
);

/*
 * Make logged-in user available
 * to every EJS page.
 */
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

/* =========================
   DATABASE
========================= */

let db;

async function connectDatabase() {
    db = await mysql.createPool({
        host: process.env.DB_HOST || '127.0.0.1',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'vehicle_booking',
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });

    const connection = await db.getConnection();

    console.log('MySQL connected');

    connection.release();
}

/* =========================
   CREATE ADMIN
========================= */

async function createAdmin() {
    const adminMobile =
        process.env.ADMIN_MOBILE || '9999999999';

    const adminPassword =
        process.env.ADMIN_PASSWORD || 'admin123';

    const [rows] = await db.execute(
        'SELECT id FROM users WHERE mobile = ?',
        [adminMobile]
    );

    if (rows.length === 0) {

        const passwordHash =
            await bcrypt.hash(adminPassword, 10);

        await db.execute(
            `INSERT INTO users
            (
                name,
                mobile,
                role,
                password,
                is_verified
            )
            VALUES (?, ?, 'admin', ?, TRUE)`,
            [
                'Administrator',
                adminMobile,
                passwordHash
            ]
        );

        console.log('Admin account created');

    } else {

        console.log('Admin account already exists');

    }
}

/* =========================
   HOME
========================= */

app.get('/', (req, res) => {

    res.render('home');

});

/* =========================
   REGISTER
========================= */

app.get('/register', (req, res) => {

    res.render('registration');

});

app.post('/register', async (req, res) => {

    try {

        const {
            name,
            mobile,
            email,
            address,
            district,
            city,
            role
        } = req.body;

        if (!name || !mobile) {

            return res.status(400).send(
                'Name and mobile number are required.'
            );

        }

        const accountRole = role === 'owner'
            ? 'owner'
            : 'customer';

        const [existing] = await db.execute(
            'SELECT id FROM users WHERE mobile = ?',
            [mobile]
        );

        if (existing.length > 0) {

            return res.send(
                'Mobile number already registered. Please login.'
            );

        }

        await db.execute(
            `INSERT INTO users
            (
                name,
                mobile,
                email,
                address,
                district,
                city,
                role
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                name,
                mobile,
                email || null,
                address || null,
                district || null,
                city || null,
                accountRole
            ]
        );

        const otp =
            Math.floor(
                100000 +
                Math.random() * 900000
            ).toString();

        req.session.otp = otp;
        req.session.otpMobile = mobile;

        console.log(
            `DEMO OTP for ${mobile}: ${otp}`
        );

        res.redirect('/verify-otp');

    } catch (error) {

        console.error(
            'Registration error:',
            error
        );

        res.status(500).send(
            'Registration failed.'
        );

    }

});

/* =========================
   VERIFY REGISTRATION OTP
========================= */

app.get('/verify-otp', (req, res) => {

    res.render('verify-otp');

});

app.post('/verify-otp', async (req, res) => {

    try {

        const { otp } = req.body;

        if (
            !req.session.otp ||
            !req.session.otpMobile
        ) {

            return res.send(
                'OTP session expired. Please register again.'
            );

        }

        if (otp !== req.session.otp) {

            return res.send(
                'Invalid OTP.'
            );

        }

        const mobile =
            req.session.otpMobile;

        const [rows] = await db.execute(
            'SELECT * FROM users WHERE mobile = ?',
            [mobile]
        );

        if (rows.length === 0) {

            return res.send(
                'User not found.'
            );

        }

        const user = rows[0];

        await db.execute(
            `UPDATE users
             SET is_verified = TRUE
             WHERE id = ?`,
            [user.id]
        );

        req.session.user = {
            id: user.id,
            name: user.name,
            mobile: user.mobile,
            role: user.role
        };

        delete req.session.otp;
        delete req.session.otpMobile;

        res.redirect('/dashboard');

    } catch (error) {

        console.error(
            'OTP verification error:',
            error
        );

        res.status(500).send(
            'OTP verification failed.'
        );

    }

});

/* =========================
   LOGIN PAGE
========================= */

app.get('/login', (req, res) => {

    res.render('login');

});

/* =========================
   LOGIN
========================= */

app.post('/login', async (req, res) => {

    try {

        const {
            mobile,
            password
        } = req.body;

        if (!mobile) {

            return res.send(
                'Mobile number is required.'
            );

        }

        const [rows] = await db.execute(
            'SELECT * FROM users WHERE mobile = ?',
            [mobile]
        );

        if (rows.length === 0) {

            return res.send(
                'User not found. Please register first.'
            );

        }

        const user = rows[0];

        /* ADMIN LOGIN */

        if (user.role === 'admin') {

            if (!password) {

                return res.send(
                    'Admin password is required.'
                );

            }

            const valid =
                await bcrypt.compare(
                    password,
                    user.password
                );

            if (!valid) {

                return res.send(
                    'Invalid admin password.'
                );

            }

            req.session.user = {
                id: user.id,
                name: user.name,
                mobile: user.mobile,
                role: user.role
            };

            return res.redirect('/admin');

        }

        /* CUSTOMER / OWNER LOGIN */

        if (!user.is_verified) {

            return res.send(
                'Your mobile number is not verified.'
            );

        }

        const otp =
            Math.floor(
                100000 +
                Math.random() * 900000
            ).toString();

        req.session.loginOtp = otp;
        req.session.loginMobile = mobile;

        console.log(
            `DEMO LOGIN OTP for ${mobile}: ${otp}`
        );

        res.render('verify-otp', {
            login: true
        });

    } catch (error) {

        console.error(
            'Login error:',
            error
        );

        res.status(500).send(
            'Login failed.'
        );

    }

});

/* =========================
   VERIFY LOGIN OTP
========================= */

app.post('/login/verify', async (req, res) => {

    try {

        const { otp } = req.body;

        if (
            !req.session.loginOtp ||
            !req.session.loginMobile
        ) {

            return res.send(
                'OTP session expired. Please login again.'
            );

        }

        if (otp !== req.session.loginOtp) {

            return res.send(
                'Invalid OTP.'
            );

        }

        const mobile =
            req.session.loginMobile;

        const [rows] = await db.execute(
            'SELECT * FROM users WHERE mobile = ?',
            [mobile]
        );

        if (rows.length === 0) {

            return res.send(
                'User not found.'
            );

        }

        const user = rows[0];

        req.session.user = {
            id: user.id,
            name: user.name,
            mobile: user.mobile,
            role: user.role
        };

        delete req.session.loginOtp;
        delete req.session.loginMobile;

        if (user.role === 'owner') {

            return res.redirect('/owner');

        }

        return res.redirect('/dashboard');

    } catch (error) {

        console.error(
            'Login OTP error:',
            error
        );

        res.status(500).send(
            'Login verification failed.'
        );

    }

});

/* =========================
   LOGOUT
========================= */

app.get('/logout', (req, res) => {

    req.session.destroy((error) => {

        if (error) {

            console.error(
                'Logout error:',
                error
            );

        }

        res.redirect('/');

    });

});

/* =========================
   CUSTOMER DASHBOARD
========================= */

app.get(
    '/dashboard',
    requireLogin,
    async (req, res) => {

        try {

            if (
                req.session.user.role === 'admin'
            ) {

                return res.redirect('/admin');

            }

            if (
                req.session.user.role === 'owner'
            ) {

                return res.redirect('/owner');

            }

            const [bookings] =
                await db.execute(
                    `SELECT
                        b.*,
                        v.category,
                        v.brand,
                        v.model,
                        v.registration_number
                     FROM bookings b
                     LEFT JOIN vehicles v
                        ON b.vehicle_id = v.id
                     WHERE b.customer_id = ?
                     ORDER BY b.created_at DESC`,
                    [req.session.user.id]
                );

            res.render('dashboard', {
                user: req.session.user,
                bookings
            });

        } catch (error) {

            console.error(
                'Dashboard error:',
                error
            );

            res.status(500).send(
                'Unable to load dashboard.'
            );

        }

    }
);

/* =========================
   BOOKING PAGE
========================= */

app.get(
    '/booking',
    requireLogin,
    (req, res) => {

        if (
            req.session.user.role !== 'customer'
        ) {

            return res.redirect('/');
        }

        res.render('booking', {
            user: req.session.user
        });

    }
);

/* =========================
   CREATE BOOKING
========================= */

app.post(
    '/booking',
    requireLogin,
    async (req, res) => {

        try {

            if (
                req.session.user.role !== 'customer'
            ) {

                return res.status(403).send(
                    'Only customers can create bookings.'
                );

            }

            const {
                vehicle_category,
                pickup_address,
                destination_address,
                pickup_date,
                pickup_time,
                return_date,
                passenger_count,
                purpose
            } = req.body;

            if (
                !vehicle_category ||
                !pickup_address ||
                !destination_address ||
                !pickup_date ||
                !pickup_time
            ) {

                return res.status(400).send(
                    'Please fill all required booking fields.'
                );

            }

            await db.execute(
                `INSERT INTO bookings
                (
                    customer_id,
                    vehicle_category,
                    pickup_address,
                    destination_address,
                    pickup_date,
                    pickup_time,
                    return_date,
                    passenger_count,
                    purpose
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    req.session.user.id,
                    vehicle_category,
                    pickup_address,
                    destination_address,
                    pickup_date,
                    pickup_time,
                    return_date || null,
                    passenger_count || 1,
                    purpose || null
                ]
            );

            res.redirect('/dashboard');

        } catch (error) {

            console.error(
                'Booking error:',
                error
            );

            res.status(500).send(
                'Booking request failed.'
            );

        }

    }
);

/* =========================
   OWNER DASHBOARD
========================= */

app.get(
    '/owner',
    requireOwner,
    async (req, res) => {

        try {

            const [vehicles] =
                await db.execute(
                    `SELECT *
                     FROM vehicles
                     WHERE owner_id = ?
                     ORDER BY created_at DESC`,
                    [req.session.user.id]
                );

            res.render('owner-dashboard', {
                user: req.session.user,
                vehicles
            });

        } catch (error) {

            console.error(
                'Owner dashboard error:',
                error
            );

            res.status(500).send(
                'Unable to load owner dashboard.'
            );

        }

    }
);

/* =========================
   VEHICLE REGISTRATION PAGE
========================= */

app.get(
    '/vehicle/register',
    requireOwner,
    (req, res) => {

        res.render('vehicle-register');

    }
);

/* =========================
   REGISTER VEHICLE
========================= */

app.post(
    '/vehicle/register',
    requireOwner,
    async (req, res) => {

        try {

            const {
                category,
                brand,
                model,
                registration_number,
                manufacturing_year,
                seating_capacity,
                color,
                district,
                city,
                price_per_day
            } = req.body;

            if (
                !category ||
                !registration_number
            ) {

                return res.status(400).send(
                    'Vehicle category and registration number are required.'
                );

            }

            await db.execute(
                `INSERT INTO vehicles
                (
                    owner_id,
                    category,
                    brand,
                    model,
                    registration_number,
                    manufacturing_year,
                    seating_capacity,
                    color,
                    district,
                    city,
                    price_per_day
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    req.session.user.id,
                    category,
                    brand || null,
                    model || null,
                    registration_number,
                    manufacturing_year || null,
                    seating_capacity || null,
                    color || null,
                    district || null,
                    city || null,
                    price_per_day || null
                ]
            );

            res.redirect('/owner');

        } catch (error) {

            console.error(
                'Vehicle registration error:',
                error
            );

            if (
                error.code === 'ER_DUP_ENTRY'
            ) {

                return res.status(400).send(
                    'Vehicle registration number already exists.'
                );

            }

            res.status(500).send(
                'Vehicle registration failed.'
            );

        }

    }
);

/* =========================
   ADMIN DASHBOARD
========================= */

app.get(
    '/admin',
    requireAdmin,
    async (req, res) => {

        try {

            const [vehicles] =
                await db.execute(
                    `SELECT
                        v.*,
                        u.name AS owner_name,
                        u.mobile AS owner_mobile
                     FROM vehicles v
                     JOIN users u
                        ON v.owner_id = u.id
                     ORDER BY v.created_at DESC`
                );

            const [bookings] =
                await db.execute(
                    `SELECT
                        b.*,
                        u.name AS customer_name,
                        u.mobile AS customer_mobile,
                        v.registration_number
                     FROM bookings b
                     JOIN users u
                        ON b.customer_id = u.id
                     LEFT JOIN vehicles v
                        ON b.vehicle_id = v.id
                     ORDER BY b.created_at DESC`
                );

            const [customers] =
                await db.execute(
                    `SELECT *
                     FROM users
                     WHERE role = 'customer'
                     ORDER BY created_at DESC`
                );

            const [owners] =
                await db.execute(
                    `SELECT *
                     FROM users
                     WHERE role = 'owner'
                     ORDER BY created_at DESC`
                );

            res.render('admin-dashboard', {
                user: req.session.user,
                vehicles,
                bookings,
                customers,
                owners
            });

        } catch (error) {

            console.error(
                'Admin dashboard error:',
                error
            );

            res.status(500).send(
                'Unable to load admin dashboard.'
            );

        }

    }
);

/* =========================
   ADMIN VEHICLE STATUS
========================= */

app.post(
    '/admin/vehicle/:id/status',
    requireAdmin,
    async (req, res) => {

        try {

            const { status } = req.body;

            const allowedStatuses = [
                'pending',
                'approved',
                'rejected',
                'unavailable'
            ];

            if (
                !allowedStatuses.includes(status)
            ) {

                return res.status(400).send(
                    'Invalid vehicle status.'
                );

            }

            await db.execute(
                `UPDATE vehicles
                 SET status = ?
                 WHERE id = ?`,
                [
                    status,
                    req.params.id
                ]
            );

            res.redirect('/admin');

        } catch (error) {

            console.error(
                'Vehicle status error:',
                error
            );

            res.status(500).send(
                'Unable to update vehicle status.'
            );

        }

    }
);

/* =========================
   ADMIN BOOKING STATUS
========================= */

app.post(
    '/admin/booking/:id/status',
    requireAdmin,
    async (req, res) => {

        try {

            const {
                status,
                vehicle_id,
                admin_note
            } = req.body;

            const allowedStatuses = [
                'pending',
                'checking',
                'confirmed',
                'rejected',
                'cancelled',
                'completed'
            ];

            if (
                !allowedStatuses.includes(status)
            ) {

                return res.status(400).send(
                    'Invalid booking status.'
                );

            }

            if (
                status === 'confirmed' &&
                !vehicle_id
            ) {

                return res.status(400).send(
                    'Please select a vehicle.'
                );

            }

            const [bookingRows] =
                await db.execute(
                    `SELECT *
                     FROM bookings
                     WHERE id = ?`,
                    [req.params.id]
                );

            if (
                bookingRows.length === 0
            ) {

                return res.status(404).send(
                    'Booking not found.'
                );

            }

            const booking =
                bookingRows[0];

            if (
                status === 'confirmed'
            ) {

                const [vehicleRows] =
                    await db.execute(
                        `SELECT *
                         FROM vehicles
                         WHERE id = ?
                         AND status = 'approved'`,
                        [vehicle_id]
                    );

                if (
                    vehicleRows.length === 0
                ) {

                    return res.status(400).send(
                        'Selected vehicle is not approved or does not exist.'
                    );

                }

                const [conflicts] =
                    await db.execute(
                        `SELECT id
                         FROM bookings
                         WHERE vehicle_id = ?
                         AND status = 'confirmed'
                         AND pickup_date = ?`,
                        [
                            vehicle_id,
                            booking.pickup_date
                        ]
                    );

                if (
                    conflicts.length > 0
                ) {

                    return res.status(400).send(
                        'Vehicle is already booked on this date.'
                    );

                }

            }

            await db.execute(
                `UPDATE bookings
                 SET
                    status = ?,
                    vehicle_id = ?,
                    admin_note = ?
                 WHERE id = ?`,
                [
                    status,
                    vehicle_id || null,
                    admin_note || null,
                    req.params.id
                ]
            );

            res.redirect('/admin');

        } catch (error) {

            console.error(
                'Booking status error:',
                error
            );

            res.status(500).send(
                'Unable to update booking.'
            );

        }

    }
);

/* =========================
   404
========================= */

app.use((req, res) => {

    res.status(404).send(
        'Page not found.'
    );

});

/* =========================
   ERROR HANDLER
========================= */

app.use((error, req, res, next) => {

    console.error(
        'Unhandled application error:',
        error
    );

    res.status(500).send(
        'Something went wrong.'
    );

});

/* =========================
   START SERVER
========================= */

async function start() {

    try {

        await connectDatabase();

        await createAdmin();

        app.listen(
            PORT,
            () => {

                console.log(
                    `Server running at http://localhost:${PORT}`
                );

            }
        );

    } catch (error) {

        console.error(
            'Unable to start application:',
            error
        );

        process.exit(1);

    }

}

start();
