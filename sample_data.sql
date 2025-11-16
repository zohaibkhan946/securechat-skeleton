-- REDACTED sample data derived from sample_data.sql
-- Sensitive fields (salts and password hashes) have been replaced

-- MySQL dump 10.13  Distrib 8.0.40, for Win64 (x86_64)
--
-- Host: localhost    Database: securechat
-- ------------------------------------------------------
-- Server version	8.0.40

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES 
('replay81351@test.com','replayuser81351',_binary '<REDACTED_SALT>','REDACTED_HASH','2025-11-16 19:41:21'),
('tamper@test.com','tamperuser',_binary '<REDACTED_SALT>','REDACTED_HASH','2025-11-16 19:20:59'),
('tamper48273@test.com','tamperuser48273',_binary '<REDACTED_SALT>','REDACTED_HASH','2025-11-16 19:32:28'),
('tamper93277@test.com','tamperuser93277',_binary '<REDACTED_SALT>','REDACTED_HASH','2025-11-16 19:36:33'),
('test@example.com','testuser',_binary '<REDACTED_SALT>','REDACTED_HASH','2025-11-16 19:09:45');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

-- Dump completed on 2025-11-17  1:40:50
