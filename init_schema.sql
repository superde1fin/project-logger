USE projectlogdb;

CREATE TABLE IF NOT EXISTS People (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    role ENUM('user', 'advisor') NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    session_token VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS Projects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_name VARCHAR(255) NOT NULL,
    week_hour_goal FLOAT NOT NULL
);

CREATE TABLE IF NOT EXISTS Assigned (
    person_id INT NOT NULL,
    project_id INT NOT NULL,
    is_supervisor BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (person_id) REFERENCES People(id),
    FOREIGN KEY (project_id) REFERENCES Projects(id)
);

CREATE TABLE IF NOT EXISTS Log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    person_id INT NOT NULL,
    project_id INT NOT NULL,
    clock_in_time DATETIME NOT NULL,
    clock_out_time DATETIME,
    FOREIGN KEY (person_id) REFERENCES People(id),
    FOREIGN KEY (project_id) REFERENCES Projects(id)
);

