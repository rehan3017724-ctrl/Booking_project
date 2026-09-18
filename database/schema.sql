CREATE DATABASE IF NOT EXISTS vehicles;

USE vehicles;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    mobile VARCHAR(20) NOT NULL UNIQUE,
    email VARCHAR(150),
    address TEXT,
    district VARCHAR(100),
    city VARCHAR(100),
    role ENUM('customer', 'owner', 'admin') DEFAULT 'customer',
    password VARCHAR(255),
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vehicles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,
    category VARCHAR(50) NOT NULL,
    brand VARCHAR(100),
    model VARCHAR(100),
    registration_number VARCHAR(50) NOT NULL UNIQUE,
    manufacturing_year INT,
    seating_capacity INT,
    color VARCHAR(50),
    district VARCHAR(100),
    city VARCHAR(100),
    price_per_day DECIMAL(10,2),
    status ENUM(
        'pending',
        'approved',
        'rejected',
        'unavailable'
    ) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (owner_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE TABLE bookings (
    id INT AUTO_INCREMENT PRIMARY KEY,

    customer_id INT NOT NULL,
    vehicle_id INT NULL,

    vehicle_category VARCHAR(50),

    pickup_address TEXT NOT NULL,
    destination_address TEXT NOT NULL,

    pickup_date DATE NOT NULL,
    pickup_time TIME NOT NULL,

    return_date DATE NULL,
    passenger_count INT DEFAULT 1,

    purpose VARCHAR(100),

    status ENUM(
        'pending',
        'checking',
        'confirmed',
        'rejected',
        'cancelled',
        'completed'
    ) DEFAULT 'pending',

    admin_note TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (customer_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    FOREIGN KEY (vehicle_id)
        REFERENCES vehicles(id)
        ON DELETE SET NULL
);
