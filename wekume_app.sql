-- Users id will be in the form 018f9b35-8d75-7d65-b503-1fdc4a4bc9b9 but later converted to binary before storage then converted to uuid7 when reading or displaying as url
CREATE TABLE users (
    id BINARY(16) PRIMARY KEY,
    name VARCHAR(255),
    gender VARCHAR(50),
    dob DATE,
    school VARCHAR(255),
    phone VARCHAR(20) UNIQUE,
    email VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE password_resets (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16),
    token VARCHAR(255),
    created_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- SafeChat
CREATE TABLE safechat_topics (
    id BINARY(16) PRIMARY KEY,
    title VARCHAR(255)
);

CREATE TABLE safechat_threads (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16),
    topic_id BINARY(16),
    created_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (topic_id) REFERENCES safechat_topics(id)
);

CREATE TABLE safechat_messages (
    id BINARY(16) PRIMARY KEY,
    thread_id BINARY(16),
    sender_id BINARY(16),
    message TEXT,
    is_admin BOOLEAN,
    created_at TIMESTAMP,
    FOREIGN KEY (thread_id) REFERENCES safechat_threads(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Shop
CREATE TABLE product_categories (
    id BINARY(16) PRIMARY KEY,
    name VARCHAR(255)
);

CREATE TABLE products (
    id BINARY(16) PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    price DECIMAL(10,2),
    stock INT,
    category_id BINARY(16),
    image_url TEXT,
    FOREIGN KEY (category_id) REFERENCES product_categories(id)
);

CREATE TABLE orders (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16),
    total DECIMAL(10,2),
    status ENUM('pending', 'paid', 'shipped', 'delivered'),
    delivery_address TEXT,
    payment_method VARCHAR(50),
    created_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE order_items (
    id BINARY(16) PRIMARY KEY,
    order_id BINARY(16),
    product_id BINARY(16),
    quantity INT,
    price DECIMAL(10,2),
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Scheduler
CREATE TABLE facilities (
    id BINARY(16) PRIMARY KEY,
    name VARCHAR(255),
    location TEXT
);

CREATE TABLE appointments (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16),
    facility_id BINARY(16),
    appointment_date DATETIME,
    confirmed BOOLEAN,
    reminder_sent BOOLEAN,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (facility_id) REFERENCES facilities(id)
);

-- Health Info
CREATE TABLE categories (
    id BINARY(16) PRIMARY KEY,
    name VARCHAR(255)
);

CREATE TABLE resources (
    id BINARY(16) PRIMARY KEY,
    title VARCHAR(255),
    content TEXT,
    type ENUM('article', 'video', 'infographic'),
    category_id BINARY(16),
    created_by BINARY(16),
    created_at TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Notifications
CREATE TABLE notifications (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16),
    title VARCHAR(255),
    message TEXT,
    read BOOLEAN DEFAULT FALSE,
    type ENUM('chat', 'order', 'appointment', 'tip'),
    created_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Security Audit Compliance
CREATE TABLE login_audits (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16),
    ip_address VARCHAR(255),
    successful BOOLEAN,
    attempted_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Events & Check-ins
CREATE TABLE events (
    id BINARY(16) PRIMARY KEY,
    title VARCHAR(255),
    location TEXT,
    event_date DATETIME
);

CREATE TABLE event_checkins (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16),
    event_id BINARY(16),
    checkin_time TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

-- School Portal Integration
CREATE TABLE school_portals (
    id BINARY(16) PRIMARY KEY,
    name VARCHAR(255),
    portal_url TEXT,
    integration_type ENUM('oauth', 'api')
);