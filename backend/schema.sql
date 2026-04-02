-- MySQL Schema for SafeJob AI
CREATE DATABASE IF NOT EXISTS safejob;

USE safejob;

CREATE TABLE IF NOT EXISTS job_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    job_text TEXT NOT NULL,
    result VARCHAR(50) NOT NULL,
    risk_score INT NOT NULL,
    flagged_keywords TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT
);

-- Optional: Add indexes for faster querying
CREATE INDEX idx_job_scans_result ON job_scans (result);

CREATE INDEX idx_job_scans_created_at ON job_scans (created_at);

USE safejob;

SELECT * FROM job_scans;