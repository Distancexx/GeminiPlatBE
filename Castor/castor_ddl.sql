# 删除已存在的castorDB数据库
# DROP DATABASE IF EXISTS CastorDB;
#
# 创建新的castorDB数据库
# CREATE DATABASE CastorDB;

# 使用castorDB数据库
USE CastorDB;


SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for castor_insts
-- ----------------------------
DROP TABLE IF EXISTS `castor_insts`;
CREATE TABLE `castor_insts`
(
    `id`               int(11)                                                          NOT NULL AUTO_INCREMENT COMMENT 'ID',
    `inst_nodeuuid`    varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '实例所属节点UUID',
    `inst_uuid`        varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '实例UUID',
    `inst_game`        varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '实例所属游戏',
    `inst_name`        varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '实例名称',
    `inst_description` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '实例描述',
    `inst_ip`          varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '实例IP',
    `inst_mainport`    int(11)                                                          NOT NULL COMMENT '实例主端口',
    `inst_path`        varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '实例路径',
    `inst_maxmem`      int(11)                                                          NOT NULL COMMENT '实例最大内存',
    `inst_maxdisk`     int(11)                                                          NOT NULL COMMENT '实例最大硬盘空间',
    PRIMARY KEY (`id`, `inst_nodeuuid`, `inst_uuid`) USING BTREE,
    INDEX `castor_instnodeuuid` (`inst_nodeuuid` ASC) USING BTREE,
    INDEX `inst_uuid` (`inst_uuid` ASC) USING BTREE,
    CONSTRAINT `castor_instnodeuuid` FOREIGN KEY (`inst_nodeuuid`) REFERENCES `castor_nodes` (`node_uuid`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB
  AUTO_INCREMENT = 1024
  CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_uca1400_ai_ci
  ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for castor_insts_perms
-- ----------------------------
DROP TABLE IF EXISTS `castor_insts_perms`;
CREATE TABLE `castor_insts_perms`
(
    `id`                   int(11)                                                          NOT NULL AUTO_INCREMENT COMMENT 'id',
    `inst_uuid`            varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '实例UUID',
    `inst_operator_userid` int(255)                                                         NOT NULL COMMENT '实例可操作者',
    `inst_operator_inst`   int(11)                                                          NULL DEFAULT NULL COMMENT '可操作者实例权限',
    `inst_operator_file`   int(11)                                                          NULL DEFAULT NULL COMMENT '可操作者文件权限',
    `inst_operator_bak`    int(11)                                                          NULL DEFAULT NULL COMMENT '可操作者备份权限',
    `inst_operator_net`    int(11)                                                          NULL DEFAULT NULL COMMENT '可操作者网络权限',
    `inst_operator_dbu`    int(11)                                                          NULL DEFAULT NULL COMMENT '可操作者数据库权限',
    `inst_operator_task`   int(11)                                                          NULL DEFAULT NULL COMMENT '可操作者计划任务权限',
    PRIMARY KEY (`id` DESC) USING BTREE,
    INDEX `inst_operator_userid` (`inst_operator_userid` ASC) USING BTREE,
    INDEX `inst_uuid` (`inst_uuid` ASC) USING BTREE,
    CONSTRAINT `castor_insts_perms_ibfk_1` FOREIGN KEY (`inst_uuid`) REFERENCES `castor_insts` (`inst_uuid`) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT `inst_operator_userid` FOREIGN KEY (`inst_operator_userid`) REFERENCES `castor_users` (`castor_userid`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB
  AUTO_INCREMENT = 13
  CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_uca1400_ai_ci
  ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for castor_nodes
-- ----------------------------
DROP TABLE IF EXISTS `castor_nodes`;
CREATE TABLE `castor_nodes`
(
    `node_id`        int(11)                                                          NOT NULL AUTO_INCREMENT COMMENT '节点ID',
    `node_uuid`      varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '节点uuid',
    `node_name`      varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '节点名称',
    `node_ip`        varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '节点IP地址',
    `node_domain`    varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NULL DEFAULT NULL COMMENT '节点域名',
    `node_port`      int(11)                                                          NOT NULL COMMENT '节点端口',
    `node_authtoken` varchar(900) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '节点认证Token',
    `node_ver`       varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci  NOT NULL COMMENT '节点版本',
    `node_os`        varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '节点系统',
    PRIMARY KEY (`node_id`, `node_uuid`) USING BTREE,
    INDEX `node_uuid` (`node_uuid` ASC) USING BTREE
) ENGINE = InnoDB
  AUTO_INCREMENT = 16
  CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_uca1400_ai_ci COMMENT = 'castor_nodes'
  ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for castor_users
-- ----------------------------
DROP TABLE IF EXISTS `castor_users`;
CREATE TABLE `castor_users`
(
    `castor_userid`     int(11)                                                          NOT NULL AUTO_INCREMENT COMMENT 'Castor用户ID',
    `castor_username`   varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'Castor用户名',
    `castor_email`      varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'Castor邮箱地址',
    `castor_password`   varchar(900) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'Castor密码',
    `castor_useravatar` varchar(900) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'Castor用户头像',
    `castor_salt`       varchar(900) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'Castor密码盐',
    `castor_usertoken`  varchar(900) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NULL     DEFAULT NULL COMMENT 'Castor用户Token',
    `castor_isadmin`    int(1)                                                           NOT NULL DEFAULT 0 COMMENT 'Castor用户系统管理员',
    PRIMARY KEY (`castor_userid`, `castor_email`) USING BTREE,
    INDEX `castor_userid` (`castor_userid` ASC) USING BTREE
) ENGINE = InnoDB
  AUTO_INCREMENT = 3
  CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_uca1400_ai_ci COMMENT = 'castor_users'
  ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for pollux_db
-- ----------------------------
DROP TABLE IF EXISTS `pollux_db`;
CREATE TABLE `pollux_db`
(
    `DB_UUID`     varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '数据库UUID',
    `DB_Name`     varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'pollux数据库名',
    `DB_Username` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'pollux数据库用户名',
    `DB_Password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'pollux数据库密码',
    `DBH_UUID`    varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'pollux数据库所属数据库主机UUID',
    `Inst_UUID`   varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '实例UUID',
    PRIMARY KEY (`DB_UUID`) USING BTREE,
    INDEX `DBH_UUID` (`DBH_UUID` ASC) USING BTREE,
    INDEX `Inst_UUID` (`Inst_UUID` ASC) USING BTREE,
    CONSTRAINT `DBH_UUID` FOREIGN KEY (`DBH_UUID`) REFERENCES `pollux_dbh_info` (`DBH_UUID`) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT `pollux_db_ibfk_1` FOREIGN KEY (`Inst_UUID`) REFERENCES `castor_insts` (`inst_uuid`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB
  CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_uca1400_ai_ci
  ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for pollux_dbh_info
-- ----------------------------
DROP TABLE IF EXISTS `pollux_dbh_info`;
CREATE TABLE `pollux_dbh_info`
(
    `DBH_UUID`     varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'pollux数据库主机UUID',
    `DBH_Name`     varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'pollux数据库主机名称',
    `DBH_IP`       varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'pollux数据库主机地址',
    `DBH_Port`     int(11)                                                          NOT NULL COMMENT 'pollux数据库主机端口',
    `DBH_Username` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'pollux数据库主机用户名',
    `DBH_Password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT 'pollux数据库主机密码',
    PRIMARY KEY (`DBH_UUID`) USING BTREE
) ENGINE = InnoDB
  CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_uca1400_ai_ci
  ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for pollux_net
-- ----------------------------
DROP TABLE IF EXISTS `pollux_net`;
CREATE TABLE `pollux_net`
(
    `port_id`   int(11)                                                          NOT NULL AUTO_INCREMENT COMMENT '端口ID',
    `node_uuid` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '所属节点UUID',
    `inst_uuid` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL COMMENT '所属实例UUID',
    `port`      int(11)                                                          NOT NULL COMMENT '端口号',
    `main`      int(1)                                                           NOT NULL COMMENT '主要',
    PRIMARY KEY (`port_id`, `node_uuid`, `inst_uuid`) USING BTREE,
    INDEX `node_uuid` (`node_uuid` ASC) USING BTREE,
    INDEX `inst_uuid` (`inst_uuid` ASC) USING BTREE,
    CONSTRAINT `inst_uuid` FOREIGN KEY (`inst_uuid`) REFERENCES `castor_insts` (`inst_uuid`) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT `node_uuid` FOREIGN KEY (`node_uuid`) REFERENCES `castor_nodes` (`node_uuid`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB
  AUTO_INCREMENT = 1
  CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_uca1400_ai_ci
  ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;

# 插入初始数据
INSERT INTO castor_users (castor_username, castor_email, castor_password, castor_useravatar, castor_salt)
VALUES ('admin', 'admin@gp.local',
        '$GPCrypto$83173be8b452d998c0d3dffeec47cb2a3f4210dcccc1b71ade843b9d75c9113b19171403350201081b9f398009b55503cd14b7ece199c299b74afefb65e07126',
        'null',
        'e65729969833bd5d5cdda689fc010af99f3d478efb0d4eab30634359fa14ac3cb17aa3384b524ce2ee928cc1135515754192896a201fa5dd30bd832dbace55bd');

