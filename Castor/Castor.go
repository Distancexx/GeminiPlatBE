// 前端部署 & Master后端服务

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"
)

type SaltAndHash struct {
	SaltStr string
	HashStr string
}

type SystemInfo struct {
	CpuLoad    float64 `json:"cpuLoad"`
	TotalMem   uint64  `json:"totalMem"`
	FreeMem    uint64  `json:"freeMem"`
	UsedMem    uint64  `json:"usedMem"`
	TotalDisk  uint64  `json:"totalDisk"`
	UsedDisk   uint64  `json:"usedDisk"`
	FreeDisk   uint64  `json:"freeDisk"`
	NetworkIn  uint64  `json:"networkIn"`
	NetworkOut uint64  `json:"networkOut"`
}

type dockerContainerArgs struct {
	Game                string   `json:"Game"`
	Eula                string   `json:"eula"`
	SetupOnly           string   `json:"setupOnly"`
	ImageName           string   `json:"imageName"`
	InstanceName        string   `json:"instanceName"`
	InstanceDescription string   `json:"instanceDescription"`
	Port                []string `json:"port"`
	HostPath            string   `json:"hostPath"`
	MinMemory           string   `json:"minMemory"`
	MaxMemory           string   `json:"maxMemory"`
	MinDisk             string   `json:"minDisk"`
	MaxDisk             string   `json:"maxDisk"`
	CoreType            string   `json:"coreType"`
	CoreFile            string   `json:"coreFile"`
	CoreVersion         string   `json:"coreVersion"`
	Operate             string   `json:"operate"`
}

type nodeInfo struct {
	NodeUUID       string `json:"node_uuid"`
	NodeName       string `json:"node_name"`
	NodeInstsCount int    `json:"node_insts_count"`
	NodeIP         string `json:"node_ip"`
	NodePort       int    `json:"node_port"`
	NodeVer        string `json:"node_ver"`
	NodeOS         string `json:"node_os"`
}

type nodeAddInfo struct {
	NodeIP        string `json:"node_ip"`
	NodePort      string `json:"node_port"`
	NodeAuthToken string `json:"node_AuthToken"`
}

type instsListInfo struct {
	InstNodeUUID    string   `json:"inst_nodeuuid"`
	InstUUID        string   `json:"inst_uuid"`
	InstGame        string   `json:"inst_game"`
	InstEula        string   `json:"inst_eula"`
	InstSetupOnly   string   `json:"inst_setuponly"`
	InstImageName   string   `json:"inst_imagename"`
	InstName        string   `json:"inst_name"`
	InstDescription string   `json:"inst_description"`
	InstIP          string   `json:"inst_ip"`
	InstMainPort    string   `json:"inst_mainport"`
	InstPorts       []string `json:"inst_ports"`
	//InstCpu_percentage string   `json:"cpu_percentage"`
	InstMinMem string `json:"inst_minmem"`
	InstMaxMem string `json:"inst_maxmem"`
	//InstMemory_usage   string   `json:"memory_usage"`
	InstMinDisk string `json:"inst_mindisk"`
	InstMaxDisk string `json:"inst_maxdisk"`
	//InstDisk_usage     string   `json:"disk_usage"`
	CoreType    string `json:"core_type"`
	CoreFile    string `json:"core_file"`
	CoreVersion string `json:"core_version"`
	Operate     string `json:"operate"`
	//AdminPerm       int    `json:"adminPerm"`
	InstPerm int `json:"instPerm"`
	FilePerm int `json:"filePerm"`
	BakPerm  int `json:"bakPerm"`
	NetPerm  int `json:"netPerm"`
	DBUPerm  int `json:"dbuPerm"`
	TaskPerm int `json:"taskPerm"`
}

type instFilesProps struct {
	CastorEmail string   `json:"castor_email"`
	Operation   string   `json:"operation"`
	InstUUID    string   `json:"inst_uuid"`
	Name        string   `json:"name"`
	Content     string   `json:"content"`
	CheckedList []string `json:"checked_list"`
}

type extendInstFilesProps struct {
	instFilesProps
	InstPath      string `json:"inst_path"`
	NodeAuthToken string `json:"node_AuthToken"`
}

func getSystemInfo() (SystemInfo, error) {
	// 获取CPU使用率
	cpuLoad, err := cpu.Percent(time.Second, false)
	if err != nil {
		return SystemInfo{}, err
	}

	// 获取内存使用情况
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return SystemInfo{}, err
	}

	// 获取硬盘使用情况
	diskStat, err := disk.Usage("/")
	if err != nil {
		return SystemInfo{}, err
	}

	// 获取网络使用情况
	netStat, err := net.IOCounters(false)
	if err != nil {
		return SystemInfo{}, err
	}

	return SystemInfo{
		CpuLoad:    cpuLoad[0],
		TotalMem:   vmStat.Total,
		FreeMem:    vmStat.Free,
		UsedMem:    vmStat.Used,
		TotalDisk:  diskStat.Total,
		FreeDisk:   diskStat.Free,
		UsedDisk:   diskStat.Used,
		NetworkIn:  netStat[0].BytesRecv,
		NetworkOut: netStat[0].BytesSent,
	}, nil
}

func checkTokenValid(db *sql.DB, castor_email string, token string) bool {
	var isTokenValid bool
	err := db.QueryRow("SELECT IF(castor_usertoken = ?, true, false) AS is_token_valid FROM CastorDB.castor_users WHERE castor_email = ?", token, castor_email).Scan(&isTokenValid)
	if err != nil {
		fmt.Println("Error checking token validity:", err)
		return false
	}
	return isTokenValid
}

func decToBin(n int) string {
	return fmt.Sprintf("%08b", n&0xFF)
}

func checkPerms(db *sql.DB, inst_uuid string, castor_email string, permName string) int {
	var permValue int
	query := fmt.Sprintf(`
    SELECT %s 
    FROM CastorDB.castor_insts_perms 
    WHERE inst_uuid = ? 
      AND inst_operator_userid = (
          SELECT castor_userid 
          FROM CastorDB.castor_users 
          WHERE castor_email = ?
      )`, permName)

	err := db.QueryRow(query, inst_uuid, castor_email).Scan(&permValue)
	if err != nil {
		fmt.Println("Error checking perms:", err)
		return 0
	}
	return permValue
}

func checkAdminPerm(db *sql.DB, castor_email string) bool {
	var isAdminPermsCheckPassed bool
	err := db.QueryRow("SELECT IF(castor_isadmin = 1, true, false) AS is_admin_perms_check_passed FROM CastorDB.castor_users WHERE castor_email = ?", castor_email).Scan(&isAdminPermsCheckPassed)

	if err != nil {
		fmt.Println("Error checking perms:", err)
		return false
	}

	return isAdminPermsCheckPassed
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func wsHandler(c *gin.Context, db *sql.DB) {
	var NodeIP = c.Query("NodeIP")
	var InstUUID = c.Query("InstUUID")
	var InstanceName = c.Query("InstanceName")
	var Operate = c.Query("Operate")
	var castorEmail = c.Query("CastorEmail")
	GPCookie, err := c.Request.Cookie("GPCookie")
	if err != nil {
		fmt.Println("GPCookie doesn't exist")
		c.JSON(401, gin.H{
			"bool":    false,
			"message": "Failed to get instance WS",
		})
	} else {
		isTokenValid := checkTokenValid(db, castorEmail, GPCookie.Value)
		if isTokenValid {
			instPermDec := checkPerms(db, InstUUID, castorEmail, "inst_operator_inst")
			instPermBin := decToBin(instPermDec)
			if instPermBin[0]-'0' == 1 {
				connToB, err := upgrader.Upgrade(c.Writer, c.Request, nil)
				if err != nil {
					fmt.Println("Failed to set WebSocket upgrade:", err)
					return
				}
				// HTTPS
				url := "ws://" + NodeIP + ":621/pollux/api/v1/instWS?InstanceName=" + InstanceName + "&Operate=" + Operate
				//	请求Pollux
				go func() {
					connToP, _, err := websocket.DefaultDialer.Dial(url, nil)
					if err != nil {
						fmt.Println("Failed connect to Pollux", err)
					}
					if connToP == nil {
						fmt.Println("Failed to establish connection to Pollux, exiting goroutine.")
						return
					}
					go func() {
						for {
							_, responseP, errP := connToP.ReadMessage()
							if errP != nil {
								fmt.Println("Error reading from Pollux:", err)
								break
							}
							if err := connToB.WriteMessage(websocket.TextMessage, responseP); err != nil {
								fmt.Println("Error writing to client:", err)
								break
							}
						}

						defer func(conn *websocket.Conn) {
							err := conn.Close()
							if err != nil {
								fmt.Println("Failed to close connToP:", err)
							}
						}(connToP)
					}()
					go func() {
						//保持 WebSocket 连接打开，确保有足够时间执行命令和日志输出
						for {
							_, responseB, err := connToB.ReadMessage()
							if err != nil {
								fmt.Println("WebSocket client disconnected:", err)
								break
							}
							//fmt.Println(string(responseB))
							if err := connToP.WriteMessage(websocket.TextMessage, responseB); err != nil {
								fmt.Println("Error writing to client:", err)
								break
							}
						}
						defer func(conn *websocket.Conn) {
							err := conn.Close()
							if err != nil {
								fmt.Println("Failed to close connToB:", err)
							}
						}(connToB)
					}()
				}()
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Not Allowed",
				})
			}
		} else {
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Token verification failed",
			})
		}
	}
}

// random salt generator
func generateSaltAndPassword(length int, verifyStr string, verifySalt string) interface{} {
	// 新加密
	if length == 64 {
		salt := make([]byte, length)
		_, err := rand.Read(salt)
		if err != nil {
		}
		hasher := sha512.New()
		hasher.Write([]byte(verifyStr))
		hasher.Write(salt)
		var hashedStr = hasher.Sum(nil)
		hashStr := "$GPCrypto$" + hex.EncodeToString(hashedStr)
		return SaltAndHash{
			SaltStr: hex.EncodeToString(salt),
			HashStr: hashStr,
		}
	} else {
		//	验证
		salt, err := hex.DecodeString(verifySalt)
		if err != nil {
			fmt.Println("Failed to decode the salt.")
		}
		hasher := sha512.New()
		hasher.Write([]byte(verifyStr))
		hasher.Write(salt)
		var hashedStr = hasher.Sum(nil)
		hashStr := "$GPCrypto$" + hex.EncodeToString(hashedStr)
		return hashStr
	}
}

// JWT generator
func generateJWT(authInfo string) (string, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	jwt_secret := os.Getenv("JWT_SECRET")
	var jwtSecret = []byte(jwt_secret)
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"authInfo": authInfo,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		fmt.Println("Failed to generate JWT")
		return "", err
	}
	return tokenString, nil
}

// AuthMiddleware JWT auth
func AuthMiddleware() gin.HandlerFunc {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	jwt_secret := os.Getenv("JWT_SECRET")
	var jwtSecret = []byte(jwt_secret)
	return func(c *gin.Context) {
		//tokenString := c.GetHeader("Authorization")
		tokenString, err := c.Cookie("GPCookie")
		if err != nil || tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供或格式错误的 Authorization token"})
			c.Abort()
			return
		}
		// 解析并验证JWT
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的 token"})
			c.Abort()
			return
		}

		// JWT验证成功，继续处理请求
		c.Next()
	}
}

// Cookie store
func setTokenCookie(c *gin.Context, jwt_Token string, maxAge int) {
	c.SetCookie(
		"GPCookie",
		jwt_Token,
		maxAge,
		"/",
		"",
		// HTTPS: true
		false,
		true,
	)
}

func generateStrongPassword(length int) (string, error) {
	if length < 4 {
		return "", fmt.Errorf("password length must be at least 4")
	}

	// 定义字符集
	lowerCase := "abcdefghijklmnopqrstuvwxyz"
	upperCase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	specials := "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
	allChars := lowerCase + upperCase + digits + specials

	// 确保密码至少包含一类字符
	var password []byte
	charSets := []string{lowerCase, upperCase, digits, specials}

	for _, charSet := range charSets {
		char, err := randomChar(charSet)
		if err != nil {
			return "", err
		}
		password = append(password, char)
	}

	// 填充剩余字符
	for i := len(password); i < length; i++ {
		char, err := randomChar(allChars)
		if err != nil {
			return "", err
		}
		password = append(password, char)
	}

	// 打乱密码
	shuffledPassword, err := shuffle(password)
	if err != nil {
		return "", err
	}

	return string(shuffledPassword), nil
}

// 从字符集中随机选择一个字符
func randomChar(charSet string) (byte, error) {
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
	if err != nil {
		return 0, err
	}
	return charSet[index.Int64()], nil
}

// 打乱字符切片
func shuffle(chars []byte) ([]byte, error) {
	n := len(chars)
	for i := range chars {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(n-i)))
		if err != nil {
			return nil, err
		}
		// 交换字符
		chars[i], chars[i+int(j.Int64())] = chars[i+int(j.Int64())], chars[i]
	}
	return chars, nil
}

// TinyAPI
func tinyAPI(db *sql.DB) {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	siteURL := os.Getenv("SITE_URL")
	gin.ForceConsoleColor()
	r := gin.Default()
	// 配置CORS中间件
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{siteURL},                                   // 允许的来源
		AllowMethods:     []string{"GET", "POST"},                             // 允许的方法
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"}, // 允许的头
		ExposeHeaders:    []string{"Content-Length", "Download-File-Name", "Content-Disposition"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// GET Query, DefaultQuery
	// POST PostForm, DefaultPostForm
	r.GET("/hello", func(c *gin.Context) {
		name := c.Query("name")
		c.JSON(200, gin.H{
			"message": "你好，" + name + "！",
		})
		fmt.Println(name)
	})

	r.POST("/castor/api/v1/login", func(c *gin.Context) {
		sub_castor_email := c.PostForm("castor_email")
		sub_castor_password := c.PostForm("castor_password")
		//	数据库查询
		dbRes := db.QueryRow("SELECT castor_password, castor_username, castor_useravatar, castor_salt, castor_isadmin FROM CastorDB.castor_users WHERE castor_email = ?", sub_castor_email)
		var (
			//castor_userid    int
			castor_username string
			//castor_email    string
			castor_password   string
			castor_useravatar string
			//castor_perm     string
			castor_salt    string
			castor_isadmin int
		)
		err := dbRes.Scan(&castor_password, &castor_username, &castor_useravatar, &castor_salt, &castor_isadmin)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Wrong email address or password",
				})
			} else {
				c.JSON(500, gin.H{
					"bool":    false,
					"message": "Server Error",
				})
			}
		} else {
			// 密码对应密文
			var hashedStr = generateSaltAndPassword(-1, sub_castor_password, castor_salt)
			if hashedStr == castor_password {
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Server Error",
					})
				} else {
					authSecret := generateSaltAndPassword(64, sub_castor_email+castor_username, "")
					if saltAndHash, ok := authSecret.(SaltAndHash); ok {
						// 生成JWT
						jwtToken, _ := generateJWT(saltAndHash.HashStr)
						_, err := db.Exec("UPDATE CastorDB.castor_users SET castor_usertoken = ? WHERE castor_email = ?", jwtToken, sub_castor_email)
						if err != nil {
							fmt.Println("Failed to update usertoken")
						}
						// 设置JWT Cookie
						setTokenCookie(c, jwtToken, 3600*24)
						c.JSON(200, gin.H{
							"bool":     true,
							"message":  "Login successful",
							"avatar":   castor_useravatar,
							"username": castor_username,
							"email":    sub_castor_email,
							"isAdmin":  castor_isadmin,
						})
					} else {
						fmt.Println("Failed to generate authSecret")
						c.JSON(500, gin.H{
							"bool":    false,
							"message": "Server Error",
						})
					}
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Wrong email address or password",
				})
			}
		}
	})

	// 需要JWT保护的路由
	auth := r.Group("/castor/api/v1")
	auth.Use(AuthMiddleware())
	// 获取实例列表 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/instsList", func(c *gin.Context) {
		castor_email := c.PostForm("castor_email")
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get instance list",
			})
		} else {
			isTokenValid := checkTokenValid(db, castor_email, GPCookie.Value)
			if isTokenValid {
				var castor_userid int
				err := db.QueryRow("SELECT castor_userid FROM CastorDB.castor_users WHERE castor_email = ?", castor_email).Scan(&castor_userid)
				if err != nil {
					fmt.Println("Failed to get userid")
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Failed to get instance list",
					})
				} else {
					isAdmin := checkAdminPerm(db, castor_email)
					if isAdmin && c.PostForm("listAll") == "true" {
						// 管理员-实例列表
						rows, err := db.Query("SELECT inst_uuid, inst_nodeuuid, inst_game, inst_name, inst_description, inst_ip, inst_mainport, inst_maxmem, inst_maxdisk FROM CastorDB.castor_insts ORDER BY id DESC")
						if err != nil {
							c.JSON(500, gin.H{
								"bool":    false,
								"message": "Failed to get instance list",
							})
							fmt.Println("Failed to get instance list", err)
						}
						var instsList []instsListInfo
						for rows.Next() {
							var inst instsListInfo
							err := rows.Scan(&inst.InstUUID, &inst.InstNodeUUID, &inst.InstGame, &inst.InstName, &inst.InstDescription, &inst.InstIP, &inst.InstMainPort, &inst.InstMaxMem, &inst.InstMaxDisk)
							//inst.InstCpu_percentage = "0%"
							//inst.InstMemory_usage = "0GB"
							//inst.InstDisk_usage = "0GB"
							instsList = append(instsList, inst)
							if err != nil {
								c.JSON(500, gin.H{
									"bool":    false,
									"message": "Failed to get instance list",
								})
								fmt.Println("Failed to get instance list", err)
							}
						}
						c.JSON(200, gin.H{
							"bool":     true,
							"instList": instsList,
						})
					} else {
						// 普通用户-实例列表
						//查询实例UUID列表
						instList, err := db.Query("SELECT inst_uuid FROM CastorDB.castor_insts_perms WHERE inst_operator_userid = ?", castor_userid)
						if err != nil {
							fmt.Println("Failed to get instance list")
							c.JSON(401, gin.H{
								"bool":    false,
								"message": "Failed to get instance list",
							})
						} else {
							var instUUIDList []string
							for instList.Next() {
								var instUUID string
								err := instList.Scan(&instUUID)
								instUUIDList = append(instUUIDList, instUUID)
								if err != nil {
									fmt.Println("Failed to get instance list")
									c.JSON(401, gin.H{
										"bool":    false,
										"message": "Failed to get instance list",
									})
								}
							}
							if err := instList.Err(); err != nil {
								fmt.Println("Failed to get instance list")
								c.JSON(401, gin.H{
									"bool":    false,
									"message": "Failed to get instance list",
								})
							}
							//查询实例列表
							var instsList []instsListInfo
							for _, instUUID := range instUUIDList {
								var inst instsListInfo
								err := db.QueryRow(`SELECT 
        													inst_nodeuuid, inst_game, inst_name, inst_description, 
        													inst_ip, inst_mainport, inst_maxmem, inst_maxdisk, 
        													inst_operator_inst, inst_operator_file, 
        													inst_operator_bak, inst_operator_net, inst_operator_dbu, inst_operator_task
    													FROM 
															CastorDB.castor_insts AS ci
    													LEFT JOIN 
        													CastorDB.castor_insts_perms AS cip 
    													ON 
        													ci.inst_uuid = cip.inst_uuid 
    													WHERE 
        													ci.inst_uuid = ? AND cip.inst_operator_userid = ?`, instUUID, castor_userid).Scan(
									&inst.InstNodeUUID, &inst.InstGame, &inst.InstName,
									&inst.InstDescription, &inst.InstIP, &inst.InstMainPort,
									&inst.InstMaxMem, &inst.InstMaxDisk,
									&inst.InstPerm, &inst.FilePerm, &inst.BakPerm,
									&inst.NetPerm, &inst.DBUPerm, &inst.TaskPerm,
								)
								inst.InstUUID = instUUID
								//inst.InstCpu_percentage = "0%"
								//inst.InstMemory_usage = "0GB"
								//inst.InstDisk_usage = "0GB"
								instsList = append(instsList, inst)
								if err != nil {
									fmt.Println("2Failed to get instance list", err)
									c.JSON(401, gin.H{
										"bool":    false,
										"message": "Failed to get instance list",
									})
								}
							}
							c.JSON(200, gin.H{
								"bool":     true,
								"instList": instsList,
							})
						}
					}
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
			}
		}
	})
	// 获取节点列表 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/nodesList", func(c *gin.Context) {
		castor_email := c.PostForm("castor_email")
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get node list",
			})
		} else {
			isTokenValid := checkTokenValid(db, castor_email, GPCookie.Value)
			if isTokenValid {
				isAdmin := checkAdminPerm(db, castor_email)
				if isAdmin {
					//rows, err := db.Query("SELECT node_uuid, node_name, , node_ip, node_port, node_ver, node_os FROM CastorDB.castor_nodes ORDER BY node_id DESC")
					rows, err := db.Query("SELECT n.node_uuid, n.node_name, n.node_ip, n.node_port,n.node_ver, n.node_os, COALESCE(i.node_insts_count, 0) AS node_insts_count FROM CastorDB.castor_nodes n LEFT JOIN (SELECT inst_nodeuuid, COUNT(*) AS node_insts_count FROM CastorDB.castor_insts GROUP BY inst_nodeuuid) i ON n.node_uuid = i.inst_nodeuuid ORDER BY n.node_id DESC;")
					if err != nil {
						c.JSON(500, gin.H{
							"bool": false,
						})
						log.Fatal(err)
					}
					var nodeList []nodeInfo
					for rows.Next() {
						var node nodeInfo
						err := rows.Scan(&node.NodeUUID, &node.NodeName, &node.NodeIP, &node.NodePort, &node.NodeVer, &node.NodeOS, &node.NodeInstsCount)
						nodeList = append(nodeList, node)
						if err != nil {
							c.JSON(500, gin.H{
								"bool": false,
							})
							log.Fatal(err)
						}
					}
					if err := rows.Err(); err != nil {
						c.JSON(500, gin.H{
							"bool": false,
						})
						log.Fatal(err)
					}
					c.JSON(200, gin.H{
						"bool":     true,
						"nodeList": nodeList,
					})
				} else {
					c.JSON(401, gin.H{
						"bool": false,
					})
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
			}
		}
	})
	// 添加|修改节点 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/nodeAddOrEdit", func(c *gin.Context) {
		castor_email := c.PostForm("castor_email")
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Add failed",
			})
		} else {
			isTokenValid := checkTokenValid(db, castor_email, GPCookie.Value)
			if isTokenValid {
				isAdmin := checkAdminPerm(db, castor_email)
				if isAdmin {
					op := c.PostForm("op")
					nodeName := c.PostForm("node_name")
					nodeIP := c.PostForm("node_ip")
					nodePort := c.PostForm("node_port")
					nodeAuthToken := c.PostForm("node_AuthToken")
					nodeAdd := nodeAddInfo{NodeIP: nodeIP, NodePort: nodePort, NodeAuthToken: nodeAuthToken}
					jsonData, err := json.Marshal(nodeAdd)
					if err != nil {
						fmt.Println("Failed to marshal json", err)
					}
					// HTTPS
					resp, err := http.Post("http://"+nodeIP+":"+nodePort+"/pollux/api/v1/bindToCastor", "application/json", bytes.NewBuffer(jsonData))
					if err != nil {
						fmt.Println("Failed to send request", err)
					}
					defer func(Body io.ReadCloser) {
						err := Body.Close()
						if err != nil {
							fmt.Println("Failed to close response body", err)
						}
					}(resp.Body)
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						fmt.Println("Failed to read response body", err)
					}
					if resp.StatusCode == 200 {
						if op == "add" {
							newNodeUUID := uuid.New()
							var node nodeInfo
							err := json.Unmarshal(body, &node)
							if err != nil {
								fmt.Println("Failed to unmarshal json", err)
							}
							_, err = db.Exec("INSERT INTO CastorDB.castor_nodes (node_uuid, node_name, node_ip, node_port, node_authtoken, node_ver, node_os) VALUES (?, ?, ?, ?, ?, ?, ?)", newNodeUUID, nodeName, nodeIP, nodePort, nodeAuthToken, node.NodeVer, node.NodeOS)
							if err != nil {
								fmt.Println("Failed to insert node", err)
							} else {
								c.JSON(200, gin.H{
									"bool":    true,
									"message": "Successful to add node",
								})
							}
						} else if op == "edit" {
							nodeUUID := c.PostForm("node_uuid")
							_, err = db.Exec("UPDATE CastorDB.castor_nodes SET node_name = ?, node_ip = ?, node_port = ?, node_authtoken = ? WHERE node_uuid = ?", nodeName, nodeIP, nodePort, nodeAuthToken, nodeUUID)
							if err != nil {
								fmt.Println("Failed to edit node")
							} else {
								c.JSON(200, gin.H{
									"bool":    true,
									"message": "Successful to edit node",
								})
							}
						} else {
							c.JSON(401, gin.H{
								"bool":    false,
								"message": "Failed to add node",
							})
						}
					} else {
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to add node",
						})
					}
				} else {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Not Allowed",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
			}
		}
	})
	// 删除节点 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/nodeDelete", func(c *gin.Context) {
		castor_email := c.PostForm("castor_email")
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to delete node",
			})
		} else {
			isTokenValid := checkTokenValid(db, castor_email, GPCookie.Value)
			if isTokenValid {
				isAdmin := checkAdminPerm(db, castor_email)
				if isAdmin {
					nodeUUID := c.PostForm("node_uuid")
					fmt.Println(nodeUUID)
					_, err := db.Exec("DELETE FROM CastorDB.castor_nodes WHERE node_uuid = ?", nodeUUID)
					if err != nil {
						fmt.Println("Failed to delete node")
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to delete node",
						})
					} else {
						c.JSON(200, gin.H{
							"bool":    true,
							"message": "Successful to delete node",
						})
					}
				} else {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Not Allowed",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
			}
		}
	})
	// 检查节点健康 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/checkNodeHealth", func(c *gin.Context) {
		castor_email := c.PostForm("castor_email")
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Add failed",
			})
		} else {
			isTokenValid := checkTokenValid(db, castor_email, GPCookie.Value)
			if isTokenValid {
				isAdmin := checkAdminPerm(db, castor_email)
				if isAdmin {
					checkNodeUUID := c.PostForm("checkNodeUUID")
					checkNodeIP := c.PostForm("checkNodeIP")
					checkNodePort := c.PostForm("checkNodePort")
					var nodeAuthToken string
					_ = db.QueryRow("SELECT node_authtoken FROM CastorDB.castor_nodes WHERE node_uuid = ?", checkNodeUUID).Scan(&nodeAuthToken)
					jsonData := `{"node_AuthToken":"` + nodeAuthToken + `"}`
					// HTTPS
					resp, err := http.Post("http://"+checkNodeIP+":"+checkNodePort+"/pollux/api/v1/checkNodeHealth", "application/json", bytes.NewBuffer([]byte(jsonData)))
					if err != nil {
						fmt.Println("Failed to send request")
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to get node health",
						})
					}
					defer func(Body io.ReadCloser) {
						err := Body.Close()
						if err != nil {
							fmt.Println("Failed to close response body")
							c.JSON(401, gin.H{
								"bool":    false,
								"message": "Failed to get node health",
							})
						}
					}(resp.Body)
					_, err = io.ReadAll(resp.Body)
					if err != nil {
						fmt.Println("Failed to read response body")
					}
					//fmt.Println(string(body))
					if resp.StatusCode == 200 {
						c.JSON(200, gin.H{
							"bool":       true,
							"nodeHealth": "Healthy",
						})
					} else {
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to get node health",
						})
					}
				} else {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Not Allowed",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
			}
		}
	})
	// 登出 - 仅验证合法性
	auth.POST("/logout", func(c *gin.Context) {
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Logout failed",
			})
		} else {
			isTokenValid := checkTokenValid(db, c.PostForm("castor_email"), GPCookie.Value)
			if isTokenValid {
				setTokenCookie(c, "", -1)
				_, err = db.Exec("UPDATE CastorDB.castor_users SET castor_usertoken = NULL WHERE castor_email = ?", c.PostForm("castor_email"))
				if err != nil {
					fmt.Println("Failed to update usertoken")
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Logout successful",
					})
				} else {
					c.JSON(200, gin.H{
						"bool":    true,
						"message": "Logout successful",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
			}
		}
	})
	// 修改用户信息 - 验证合法性 + 唯一性
	auth.POST("/updateUserInfo", func(c *gin.Context) {
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Modification failed",
			})
		} else {
			isTokenValid := checkTokenValid(db, c.PostForm("castor_email"), GPCookie.Value)
			if isTokenValid {
				if c.PostForm("castor_password") == "" {
					_, err := db.Exec("UPDATE CastorDB.castor_users SET castor_email = ?, castor_username = ? WHERE castor_email = ?", c.PostForm("castor_newEmail"), c.PostForm("castor_newUsername"), c.PostForm("castor_email"))
					if err != nil {
						fmt.Println("Failed to update user info")
					} else {
						c.JSON(200, gin.H{
							"bool":    true,
							"message": "Modification successful",
						})
					}
				} else if c.PostForm("castor_password") != "" {
					dbRes := db.QueryRow("SELECT castor_password, castor_salt FROM CastorDB.castor_users WHERE castor_email = ?", c.PostForm("castor_email"))
					var (
						castor_password string
						castor_salt     string
					)
					err := dbRes.Scan(&castor_password, &castor_salt)
					if err != nil {
						if errors.Is(err, sql.ErrNoRows) {
							c.JSON(401, gin.H{
								"bool":    false,
								"message": "Wrong email address or password",
							})
						} else {
							c.JSON(500, gin.H{
								"bool":    false,
								"message": "Server Error",
							})
						}
					} else {
						// 密码对应密文
						var hashedStr = generateSaltAndPassword(-1, c.PostForm("castor_password"), castor_salt)
						if hashedStr == castor_password {
							newSaltAndPassword := generateSaltAndPassword(64, c.PostForm("castor_newPassword"), "")
							if saltAndHash, ok := newSaltAndPassword.(SaltAndHash); ok {
								_, err := db.Exec("UPDATE CastorDB.castor_users SET castor_password = ?, castor_salt = ? WHERE castor_email = ?", saltAndHash.HashStr, saltAndHash.SaltStr, c.PostForm("castor_email"))
								if err != nil {
									fmt.Println("Failed to update user info")
								} else {
									c.JSON(200, gin.H{
										"bool":    true,
										"message": "Modification successful",
									})
								}
							} else {
								fmt.Println("Failed to generate authSecret")
								c.JSON(500, gin.H{
									"bool":    false,
									"message": "Wrong email address or password",
								})
							}
						} else {
							c.JSON(401, gin.H{
								"bool":    false,
								"message": "Wrong email address or password",
							})
						}
					}
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
			}
		}
	})
	// 获取系统信息 - 仅验证合法性
	auth.POST("/getSystemInfo", func(c *gin.Context) {
		targetHostIP := c.PostForm("targetHostIP")
		targetHostPort := c.PostForm("targetHostPort")
		if targetHostIP == "localhost" {
			systemInfo, err := getSystemInfo()
			if err != nil {
				c.JSON(500, gin.H{
					"bool":    false,
					"message": "Server Error",
				})
			} else {
				c.JSON(200, gin.H{
					"bool":       true,
					"systemInfo": systemInfo,
				})
			}
		} else {
			// HTTPS
			resp, err := http.Post("http://"+targetHostIP+":"+targetHostPort+"/pollux/api/v1/getSystemInfo", "application/json", nil)
			if err != nil {
				fmt.Println("Failed to send request", err)
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					fmt.Println("Failed to close response body", err)
				}
			}(resp.Body)
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Failed to read response body", err)
			}
			if resp.StatusCode == 200 {
				var polluxSystemInfo SystemInfo
				err := json.Unmarshal(body, &polluxSystemInfo)
				if err != nil {
					fmt.Println("Failed to unmarshal json", err)
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Failed to get system info",
					})
				} else {
					c.JSON(200, gin.H{
						"bool":       true,
						"systemInfo": polluxSystemInfo,
					})
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Failed to get system info",
				})
			}
		}
	})
	// 实例创建|删除|修改 - 验证合法性 + 唯一性 + 鉴权 (修改未完成)
	auth.POST("/instAddDelEdit", func(c *gin.Context) {
		castor_email := c.PostForm("castor_email")
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to AddDelEdit instance111",
			})
		} else {
			isTokenValid := checkTokenValid(db, castor_email, GPCookie.Value)
			if isTokenValid {
				isAdmin := checkAdminPerm(db, castor_email)
				if isAdmin {
					var NodeUUID = c.PostForm("InstNodeUUID")
					var NodeIP string
					_ = db.QueryRow("SELECT node_ip FROM CastorDB.castor_nodes WHERE node_uuid = ?", NodeUUID).Scan(&NodeIP)
					var args instsListInfo
					if err := c.ShouldBind(&args); err != nil {
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to AddDelEdit instance222",
						})
					}
					fmt.Println(args)
					fmt.Println(castor_email)
					if args.Operate == "add" {
						var InstanceUUID = uuid.New()
						//var HostPath = "/var/GeminiPlatform/" + InstanceUUID.String()
						//args.InstHostPath = HostPath
						args.InstUUID = InstanceUUID.String()
						args.InstMinMem = c.PostForm("InstMinMem") + "G"
						args.InstMaxMem = c.PostForm("InstMaxMem") + "G"
						args.InstMinDisk = c.PostForm("InstMinDisk") + "G"
						args.InstMaxDisk = c.PostForm("InstMaxDisk") + "G"
						jsonData, err := json.Marshal(args)
						if err != nil {
							fmt.Println("Failed to marshal json", err)
						}
						// HTTPS
						resp, err := http.Post("http://"+NodeIP+":621/pollux/api/v1/instAddDelEdit", "application/json", bytes.NewBuffer(jsonData))
						if err != nil {
							fmt.Println("Failed to send request", err)
							c.JSON(401, gin.H{
								"bool":    false,
								"message": "Failed to AddDelEdit instance",
							})
						}
						if resp.StatusCode == 200 {
							MaxMemory, _ := strconv.Atoi(c.PostForm("InstMaxMem"))
							MaxDisk, _ := strconv.Atoi(c.PostForm("InstMaxDisk"))
							_, err = db.Exec("INSERT INTO CastorDB.castor_insts (inst_nodeuuid, inst_uuid, inst_game, inst_name, inst_description, inst_ip, inst_mainport, inst_path, inst_maxmem, inst_maxdisk) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", NodeUUID, args.InstUUID, args.InstGame, args.InstName, args.InstDescription, NodeIP, args.InstPorts[0], "/var/GeminiPlatform/"+args.InstUUID, MaxMemory, MaxDisk)
							if err != nil {
								fmt.Println("Failed to insert instance", err)
								c.JSON(500, gin.H{
									"bool":    false,
									"message": "Failed to AddDelEdit instance",
								})
							} else {
								_, err = db.Exec("INSERT INTO CastorDB.castor_insts_perms (inst_uuid,inst_operator_userid,inst_operator_inst,inst_operator_file,inst_operator_bak,inst_operator_net,inst_operator_dbu,inst_operator_task) VALUES (?, (SELECT castor_userid FROM CastorDB.castor_users WHERE castor_email = ?), 255, 63, 31, 15, 127, 15)", InstanceUUID, castor_email)
								if err != nil {
									fmt.Println("Failed to insert instance perms", err)
									c.JSON(500, gin.H{
										"bool":    false,
										"message": "Failed to AddDelEdit instance",
									})
								} else {
									c.JSON(200, gin.H{
										"bool":    true,
										"message": "Successful to add instance",
									})
								}
							}
						} else {
							c.JSON(401, gin.H{
								"bool":    false,
								"message": "Failed to AddDelEdit instance",
							})
						}
					} else if args.Operate == "del" {
						var InstanceUUID = c.PostForm("InstUUID")
						_, err = db.Exec("DELETE FROM CastorDB.castor_insts WHERE inst_uuid = ?", InstanceUUID)
						if err != nil {
							fmt.Println("Failed to delete instance", err)
							c.JSON(500, gin.H{
								"bool":    false,
								"message": "Failed to AddDelEdit instance333",
							})
						} else {
							c.JSON(200, gin.H{
								"bool":    true,
								"message": "Successful to delete instance444",
							})
						}
					} else {
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to AddDelEdit instance555",
						})
					}
				} else {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Not Allowed",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
			}
		}
	})
	// 实例文件管理 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/instFiles", func(c *gin.Context) {
		var instFiles extendInstFilesProps
		if err := c.ShouldBind(&instFiles); err != nil {
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get instance files",
			})
		}
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get instance files",
			})
		} else {
			isTokenValid := checkTokenValid(db, instFiles.CastorEmail, GPCookie.Value)
			if isTokenValid {
				operation := instFiles.Operation
				instUUID := instFiles.InstUUID
				var instNodeUUID string
				var nodeIP string
				_ = db.QueryRow("SELECT inst_nodeuuid,inst_path FROM CastorDB.castor_insts WHERE inst_uuid = ?", instUUID).Scan(&instNodeUUID, &instFiles.InstPath)
				//_ = db.QueryRow("SELECT inst_path FROM CastorDB.castor_insts WHERE inst_uuid = ?", instUUID).Scan(&instFiles.InstPath)
				_ = db.QueryRow("SELECT node_ip,node_authtoken FROM CastorDB.castor_nodes WHERE node_uuid = ?", instNodeUUID).Scan(&nodeIP, &instFiles.NodeAuthToken)
				//_ = db.QueryRow("SELECT node_authtoken FROM CastorDB.castor_nodes WHERE node_uuid = ?", instNodeUUID).Scan(&instFiles.NodeAuthToken)
				filePermDec := checkPerms(db, instFiles.InstUUID, instFiles.CastorEmail, "inst_operator_file")
				filePermBin := decToBin(filePermDec)
				jsonData, err := json.Marshal(instFiles)
				if err != nil {
					fmt.Println("Failed to marshal json", err)
				}
				if (operation == "list" || operation == "readFile") && filePermBin[5]-'0' == 1 {
					// HTTPS
					resp, err := http.Post("http://"+nodeIP+":621/pollux/api/v1/instFiles", "application/json", bytes.NewBuffer(jsonData))
					if err != nil {
						fmt.Println("Failed to send request", err)
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to get instance files",
						})
					}
					defer func(Body io.ReadCloser) {
						err := Body.Close()
						if err != nil {
							fmt.Println("Failed to close response body", err)
						}
					}(resp.Body)
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						fmt.Println("Failed to read response body", err)
					}
					type filesList struct {
						FileInfo []map[string]interface{} `json:"files"`
						Content  string                   `json:"content"`
					}
					var files filesList
					err = json.Unmarshal(body, &files)
					if err != nil {
						fmt.Println("Failed to unmarshal json", err)
					}
					c.JSON(200, gin.H{
						"bool":    true,
						"list":    files.FileInfo,
						"content": files.Content,
					})
				} else if operation == "writeFile" && filePermBin[4]-'0' == 1 {
					// HTTPS
					resp, err := http.Post("http://"+nodeIP+":621/pollux/api/v1/instFiles", "application/json", bytes.NewBuffer(jsonData))
					if err != nil {
						fmt.Println("Failed to send request", err)
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to save instance file",
						})
					}
					if resp.StatusCode == 200 {
						c.JSON(200, gin.H{
							"bool":    true,
							"message": "Successful to save instance file",
						})
					} else {
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to save instance file",
						})
					}
				} else if (operation == "createFile" || operation == "createDir") && filePermBin[2]-'0' == 1 {
					// HTTPS
					resp, err := http.Post("http://"+nodeIP+":621/pollux/api/v1/instFiles", "application/json", bytes.NewBuffer(jsonData))
					if err != nil {
						fmt.Println("Failed to send request", err)
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to create instance file/Dir",
						})
					}
					if resp.StatusCode == 200 {
						c.JSON(200, gin.H{
							"bool":    true,
							"message": "Successful to create instance file/Dir",
						})
					} else {
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to create instance file/Dir",
						})
					}
				} else if operation == "delete" && filePermBin[3]-'0' == 1 {
					// HTTPS
					resp, err := http.Post("http://"+nodeIP+":621/pollux/api/v1/instFiles", "application/json", bytes.NewBuffer(jsonData))
					if err != nil {
						fmt.Println("Failed to send request", err)
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to delete instance file/Dir",
						})
					}
					if resp.StatusCode == 200 {
						c.JSON(200, gin.H{
							"bool":    true,
							"message": "Successful to delete instance file/Dir",
						})
					} else {
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to delete instance file/Dir",
						})
					}
				} else {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Not Allowed",
					})
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
			}
		}
	})
	// 实例文件下载 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/instFileDownload", func(c *gin.Context) {
		type instFileDownloadType struct {
			CastorEmail    string   `json:"CastorEmail"`
			InstUUID       string   `json:"InstUUID"`
			Node_AuthToken string   `json:"Node_AuthToken"`
			InstPath       string   `json:"InstPath"`
			FilesName      []string `json:"FilesName"`
		}
		var instFileDownload instFileDownloadType
		if err := c.ShouldBind(&instFileDownload); err != nil {
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get instance files",
			})
			return
		}
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get instance files",
			})
			return
		} else {
			isTokenValid := checkTokenValid(db, instFileDownload.CastorEmail, GPCookie.Value)
			if isTokenValid {
				if instFileDownload.InstUUID == "" || instFileDownload.FilesName == nil {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Missing parameters",
					})
					return
				} else {
					var instNodeUUID string
					var nodeIP string
					_ = db.QueryRow("SELECT inst_nodeuuid,inst_path FROM CastorDB.castor_insts WHERE inst_uuid = ?", instFileDownload.InstUUID).Scan(&instNodeUUID, &instFileDownload.InstPath)
					//_ = db.QueryRow("SELECT inst_path FROM CastorDB.castor_insts WHERE inst_uuid = ?", instFileDownload.InstUUID).Scan(&instFileDownload.InstPath)
					_ = db.QueryRow("SELECT node_ip,node_authtoken FROM CastorDB.castor_nodes WHERE node_uuid = ?", instNodeUUID).Scan(&nodeIP, &instFileDownload.Node_AuthToken)
					//_ = db.QueryRow("SELECT node_authtoken FROM CastorDB.castor_nodes WHERE node_uuid = ?", instNodeUUID).Scan(&instFileDownload.Node_AuthToken)
					jsonData, err := json.Marshal(instFileDownload)
					if err != nil {
						fmt.Println("Failed to marshal json", err)
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to download instance file",
						})
						return
					}
					filePermDec := checkPerms(db, instFileDownload.InstUUID, instFileDownload.CastorEmail, "inst_operator_file")
					filePermBin := decToBin(filePermDec)
					if filePermBin[5]-'0' == 1 {
						// HTTPS
						resp, err := http.Post("http://"+nodeIP+":621/pollux/api/v1/instFileDownload", "application/json", bytes.NewBuffer(jsonData))
						if err != nil {
							fmt.Println("Failed to send request", err)
							c.JSON(401, gin.H{
								"bool":    false,
								"message": "Failed to download instance file",
							})
						}
						defer func(Body io.ReadCloser) {
							err := Body.Close()
							if err != nil {
								fmt.Println("Failed to close response body", err)
							}
						}(resp.Body)
						// 复制 Pollux 的响应头
						for k, v := range resp.Header {
							for _, v := range v {
								c.Writer.Header().Add(k, v)
							}
						}
						// 将 Pollux 的响应体直接流式转发到前端
						c.Status(resp.StatusCode)
						_, _ = io.Copy(c.Writer, resp.Body)
					} else {
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Not Allowed",
						})
						return
					}
				}
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Token verification failed",
				})
				return
			}
		}
	})
	// 实例文件上传 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/instFileUpload", func(c *gin.Context) {
		GPCookie, err := c.Request.Cookie("GPCookie")
		castorEmail := c.PostForm("castor_email")
		instUUID := c.PostForm("instUUID")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get instance files",
			})
			return
		}
		isTokenValid := checkTokenValid(db, castorEmail, GPCookie.Value)
		if isTokenValid {
			filePermDec := checkPerms(db, instUUID, castorEmail, "inst_operator_file")
			filePermBin := decToBin(filePermDec)
			if filePermBin[2]-'0' == 1 {
				uploadFile, err := c.FormFile("uploadFile")
				var instNodeUUID string
				var nodeIP string
				var instPath string
				var nodeAuthToken string
				_ = db.QueryRow("SELECT inst_nodeuuid,inst_path FROM CastorDB.castor_insts WHERE inst_uuid = ?", instUUID).Scan(&instNodeUUID, &instPath)
				//_ = db.QueryRow("SELECT inst_path FROM CastorDB.castor_insts WHERE inst_uuid = ?", instUUID).Scan(&instPath)
				_ = db.QueryRow("SELECT node_ip,node_authtoken FROM CastorDB.castor_nodes WHERE node_uuid = ?", instNodeUUID).Scan(&nodeIP, &nodeAuthToken)
				//_ = db.QueryRow("SELECT node_authtoken FROM CastorDB.castor_nodes WHERE node_uuid = ?", instNodeUUID).Scan(&nodeAuthToken)
				if uploadFile == nil || err != nil {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Failed to upload instance file / Or no file selected",
					})
					return
				}
				srcFile, err := uploadFile.Open()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				defer func(srcFile multipart.File) {
					err := srcFile.Close()
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
						return
					}
				}(srcFile)
				body := &bytes.Buffer{}
				writer := multipart.NewWriter(body)
				part, err := writer.CreateFormFile("uploadFile", uploadFile.Filename)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				_, err = io.Copy(part, srcFile)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				// 添加 instPath 字段
				err = writer.WriteField("InstPath", instPath)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				// 添加 nodeAuthToken 字段
				err = writer.WriteField("Node_AuthToken", nodeAuthToken)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				err = writer.Close()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				// HTTPS
				// post请求pollux并传递instPath和nodeAuthToken以及文件
				resp, err := http.Post("http://"+nodeIP+":621/pollux/api/v1/instFileUpload", writer.FormDataContentType(), body)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				defer func(Body io.ReadCloser) {
					err := Body.Close()
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
						return
					}
				}(resp.Body)
				var result map[string]interface{}
				if resp.StatusCode == http.StatusOK {
					err := json.NewDecoder(resp.Body).Decode(&result)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
						return
					}
					fmt.Println(result)
					c.JSON(http.StatusOK, result)
				} else {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload file."})
					return
				}
			}
		} else {
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Token verification failed",
			})
			return
		}
	})
	// 实例参数 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/instStats", func(c *gin.Context) {
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get instance stats",
			})
			return
		}
		type instInfoType struct {
			CastorEmail    string `json:"CastorEmail"`
			InstUUID       string `json:"InstUUID"`
			InstName       string `json:"InstName"`
			InstPath       string `json:"InstPath"`
			Node_AuthToken string `json:"Node_AuthToken"`
		}
		var instInfo instInfoType
		err = c.ShouldBind(&instInfo)
		if err != nil {
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get instance stats",
			})
			return
		}
		isTokenValid := checkTokenValid(db, instInfo.CastorEmail, GPCookie.Value)
		if isTokenValid {
			instPermDec := checkPerms(db, instInfo.InstUUID, instInfo.CastorEmail, "inst_operator_inst")
			instPermBin := decToBin(instPermDec)
			if instPermBin[0]-'0' == 1 {
				var instNodeUUID string
				var nodeIP string
				_ = db.QueryRow("SELECT inst_nodeuuid,inst_name,inst_path FROM CastorDB.castor_insts WHERE inst_uuid = ?", instInfo.InstUUID).Scan(&instNodeUUID, &instInfo.InstName, &instInfo.InstPath)
				_ = db.QueryRow("SELECT node_ip,node_authtoken FROM CastorDB.castor_nodes WHERE node_uuid = ?", instNodeUUID).Scan(&nodeIP, &instInfo.Node_AuthToken)
				jsonData, err := json.Marshal(instInfo)
				if err != nil {
					fmt.Println("Failed to marshal json", err)
					return
				}
				// HTTPS
				resp, err := http.Post("http://"+nodeIP+":621/pollux/api/v1/instStats", "application/json", bytes.NewBuffer(jsonData))
				if err != nil {
					fmt.Println("Failed to send request", err)
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Failed to get instance stats",
					})
					return
				}
				defer func(Body io.ReadCloser) {
					err := Body.Close()
					if err != nil {
						fmt.Println("Failed to close response body", err)
					}
				}(resp.Body)
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Println("Failed to read response body", err)
					return
				}
				var containerStats interface{}
				err = json.Unmarshal(body, &containerStats)
				if err != nil {
					fmt.Println("Failed to unmarshal json", err)
					return
				}
				c.JSON(200, gin.H{
					"bool":   true,
					"result": containerStats,
				})
				return
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Not Allowed",
				})
				return
			}
		} else {
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Token verification failed",
			})
			return
		}
	})
	// 数据库管理 - 验证合法性 + 唯一性 + 鉴权
	auth.POST("/dbManage", func(c *gin.Context) {
		GPCookie, err := c.Request.Cookie("GPCookie")
		if err != nil {
			fmt.Println("GPCookie doesn't exist")
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get instance files",
			})
			return
		}
		type dbManageType struct {
			CastorEmail string `json:"CastorEmail"`
			Operation   string `json:"Operation"`
			DBHUUID     string `json:"DBHUUID"`
			DBHName     string `json:"DBHName"`
			DBHIP       string `json:"DBHIP"`
			DBHPort     string `json:"DBHPort"`
			DBHUsername string `json:"DBHUsername"`
			DBHPassword string `json:"DBHPassword"`
			InstUUID    string `json:"InstUUID"`
			DBUUID      string `json:"DBUUID"`
			DBName      string `json:"DBName"`
			//DBHNodeUUID string `json:"DBHNodeUUID"`
		}
		var dbManageParams dbManageType
		err = c.ShouldBind(&dbManageParams)
		if err != nil {
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Failed to get DB info.",
			})
			return
		}
		isTokenValid := checkTokenValid(db, dbManageParams.CastorEmail, GPCookie.Value)
		if isTokenValid {
			dbuPermDec := checkPerms(db, dbManageParams.InstUUID, dbManageParams.CastorEmail, "inst_operator_dbu")
			dbuPermBin := decToBin(dbuPermDec)
			// 添加数据库主机信息
			if dbManageParams.Operation == "addDBH" && checkAdminPerm(db, dbManageParams.CastorEmail) {
				if dbManageParams.DBHIP == "" || dbManageParams.DBHName == "" || dbManageParams.DBHPassword == "" || dbManageParams.DBHUsername == "" || dbManageParams.DBHPort == "" {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Missing parameters",
					})
					return
				}
				// 测试连接数据库主机
				dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/?charset=utf8&parseTime=True&loc=Local",
					dbManageParams.DBHUsername, dbManageParams.DBHPassword, dbManageParams.DBHIP, dbManageParams.DBHPort)
				dbTest, err := sql.Open("mysql", dsn)
				if err != nil || dbTest.Ping() != nil {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Failed to connect to the database host",
					})
					return
				} else {
					dbManageParams.DBHUUID = uuid.New().String()
					_, err = db.Exec("INSERT INTO CastorDB.pollux_dbh_info (DBH_UUID, DBH_Name, DBH_IP, DBH_Port, DBH_Username, DBH_Password) VALUES (?, ?, ?, ?, ?, ?)", dbManageParams.DBHUUID, dbManageParams.DBHName, dbManageParams.DBHIP, dbManageParams.DBHPort, dbManageParams.DBHUsername, dbManageParams.DBHPassword)
					if err != nil {
						c.JSON(401, gin.H{
							"bool":    false,
							"message": "Failed to add database host",
						})
						return
					}
					c.JSON(200, gin.H{
						"bool":    true,
						"message": "Successful to add database host",
					})
					return
				}
			} else if dbManageParams.Operation == "delDBH" && checkAdminPerm(db, dbManageParams.CastorEmail) {
				// 删除数据库主机信息
				if dbManageParams.DBHUUID == "" {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Missing parameters",
					})
					return
				}
				var exists bool
				err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM CastorDB.pollux_dbh_info WHERE DBH_UUID = ?)", dbManageParams.DBHUUID).Scan(&exists)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to check database host existence",
					})
					return
				}
				if !exists {
					c.JSON(404, gin.H{
						"bool":    false,
						"message": "Database host not found",
					})
					return
				}
				_, err = db.Exec("DELETE FROM CastorDB.pollux_dbh_info WHERE DBH_UUID = ?", dbManageParams.DBHUUID)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to delete database host",
					})
					return
				}

				c.JSON(200, gin.H{
					"bool":    true,
					"message": "Successful to delete database host",
				})
				return
			} else if dbManageParams.Operation == "listDBH" && checkAdminPerm(db, dbManageParams.CastorEmail) {
				// 列出数据库主机信息
				dbhInfo, err := db.Query("SELECT DBH_UUID, DBH_Name, DBH_IP, DBH_Port, DBH_Username FROM CastorDB.pollux_dbh_info")
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to list database host",
					})
					return
				}
				var dbhList []map[string]interface{}
				for dbhInfo.Next() {
					var (
						DBH_UUID     string
						DBH_Name     string
						DBH_IP       string
						DBH_Port     string
						DBH_Username string
					)
					err = dbhInfo.Scan(&DBH_UUID, &DBH_Name, &DBH_IP, &DBH_Port, &DBH_Username)
					if err != nil {
						c.JSON(500, gin.H{
							"bool":    false,
							"message": "Failed to list database host",
						})
						return
					}
					dbhList = append(dbhList, map[string]interface{}{
						"DBH_UUID":     DBH_UUID,
						"DBH_Name":     DBH_Name,
						"DBH_IP":       DBH_IP,
						"DBH_Port":     DBH_Port,
						"DBH_Username": DBH_Username,
					})
				}
				c.JSON(200, gin.H{
					"bool":    true,
					"DBHList": dbhList,
				})
				return
			} else if dbManageParams.Operation == "listDB" && dbuPermBin[4]-'0' == 1 {
				// 列出数据库信息
				type dbListType struct {
					DBH_IP      string `json:"DBH_IP"`
					DBH_Port    string `json:"DBH_Port"`
					DB_Name     string `json:"DB_Name"`
					DB_Username string `json:"DB_Username"`
					DB_Password string `json:"DB_Password"`
					DB_UUID     string `json:"DB_UUID"`
				}
				var dbList []dbListType
				type DBH_UUIDsType struct {
					DBH_Name string `json:"DBH_Name"`
					DBH_UUID string `json:"DBH_UUID"`
				}
				var DBH_UUIDs []DBH_UUIDsType
				DBs, err := db.Query("SELECT DB_Name, DB_Username, DB_Password,DB_UUID,DBH_UUID FROM CastorDB.pollux_db WHERE Inst_UUID = ?", dbManageParams.InstUUID)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to list database",
					})
					return
				}
				for DBs.Next() {
					var (
						DBH_UUID    string
						DBH_IP      string
						DBH_Port    string
						DB_Name     string
						DB_Username string
						DB_Password string
						DB_UUID     string
					)
					err = DBs.Scan(&DB_Name, &DB_Username, &DB_Password, &DB_UUID, &DBH_UUID)
					if err != nil {
						c.JSON(500, gin.H{
							"bool":    false,
							"message": "Failed to list database",
						})
						return
					}
					_ = db.QueryRow("SELECT DBH_IP, DBH_Port FROM CastorDB.pollux_dbh_info WHERE DBH_UUID = ?", DBH_UUID).Scan(&DBH_IP, &DBH_Port)
					dbList = append(dbList, dbListType{
						DBH_IP:      DBH_IP,
						DBH_Port:    DBH_Port,
						DB_Name:     DB_Name,
						DB_Username: DB_Username,
						DB_Password: DB_Password,
						DB_UUID:     DB_UUID,
					})
				}
				DBHs, err := db.Query("SELECT DBH_Name, DBH_UUID FROM CastorDB.pollux_dbh_info")
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to list database",
					})
					return
				}
				for DBHs.Next() {
					var (
						DBH_UUID string
						DBH_Name string
					)
					err = DBHs.Scan(&DBH_Name, &DBH_UUID)
					if err != nil {
						c.JSON(500, gin.H{
							"bool":    false,
							"message": "Failed to list database",
						})
						return
					}
					DBH_UUIDs = append(DBH_UUIDs, DBH_UUIDsType{
						DBH_Name: DBH_Name,
						DBH_UUID: DBH_UUID,
					})
				}
				c.JSON(200, gin.H{
					"bool":     true,
					"DBList":   dbList,
					"DBHUUIDs": DBH_UUIDs,
				})
				return
			} else if dbManageParams.Operation == "delDB" && dbuPermBin[2]-'0' == 1 {
				// 通过dbManageParams.DBUUID获取DBH_IP、DBH_Port、DBH_Username、DBH_Password，并连接数据库
				var (
					DBH_IP       string
					DBH_Port     string
					DBH_Username string
					DBH_Password string
				)
				_ = db.QueryRow("SELECT DBH_IP, DBH_Port, DBH_Username, DBH_Password FROM CastorDB.pollux_dbh_info WHERE DBH_UUID = (SELECT DBH_UUID FROM CastorDB.pollux_db WHERE DB_UUID = ?)", dbManageParams.DBUUID).Scan(&DBH_IP, &DBH_Port, &DBH_Username, &DBH_Password)
				dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/?charset=utf8&parseTime=True&loc=Local", DBH_Username, DBH_Password, DBH_IP, DBH_Port)
				DBH, err := sql.Open("mysql", dsn)
				if err != nil || DBH.Ping() != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to connect to the database host",
					})
					return
				}
				//通过dbManageParams.DBUUID获取DB_Name，并删除数据库
				var (
					DB_Name     string
					DB_Username string
				)
				_ = db.QueryRow("SELECT DB_Name, DB_Username FROM CastorDB.pollux_db WHERE DB_UUID = ?", dbManageParams.DBUUID).Scan(&DB_Name, &DB_Username)
				dropDBSQL := fmt.Sprintf("DROP DATABASE %s", DB_Name)
				_, err = DBH.Exec(dropDBSQL)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to delete database",
					})
					return
				}
				dropUserSQL := fmt.Sprintf("DROP USER %s", DB_Username)
				_, err = DBH.Exec(dropUserSQL)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to delete user",
					})
					return
				}
				// 删除数据库信息
				_, err = db.Exec("DELETE FROM CastorDB.pollux_db WHERE DB_UUID = ?", dbManageParams.DBUUID)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to delete database",
					})
					return
				}
				c.JSON(200, gin.H{
					"bool":    true,
					"message": "Successful to delete database",
				})
				return
			} else if dbManageParams.Operation == "addDB" && dbuPermBin[1]-'0' == 1 {
				//	新建数据库
				if dbManageParams.DBName == "" {
					c.JSON(401, gin.H{
						"bool":    false,
						"message": "Missing parameters",
					})
					return
				}
				DB_UUID := uuid.New().String()
				DB_Name := "GPDBN_" + dbManageParams.DBName
				DB_Username := "GPDBU_" + dbManageParams.DBName
				DB_Password, err := generateStrongPassword(16)
				fmt.Println(DB_UUID, DB_Name, DB_Username, DB_Password)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to generate password",
					})
					return
				}
				// 通过dbManageParams.DBHUUID获取DBH_IP、DBH_Port、DBH_Username、DBH_Password，并连接数据库
				var (
					DBH_IP       string
					DBH_Port     string
					DBH_Username string
					DBH_Password string
				)
				_ = db.QueryRow("SELECT DBH_IP, DBH_Port, DBH_Username, DBH_Password FROM CastorDB.pollux_dbh_info WHERE DBH_UUID = ?", dbManageParams.DBHUUID).Scan(&DBH_IP, &DBH_Port, &DBH_Username, &DBH_Password)
				dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/?charset=utf8&parseTime=True&loc=Local", DBH_Username, DBH_Password, DBH_IP, DBH_Port)
				DBH, err := sql.Open("mysql", dsn)
				if err != nil || DBH.Ping() != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to connect to the database host",
					})
					return
				}
				fmt.Println(DBH_IP, DBH_Port, DBH_Username, DBH_Password)
				//创建用户和数据库
				createUserSQL := fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s'", DB_Username, DB_Password)
				_, err = DBH.Exec(createUserSQL)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to create user",
					})
					return
				}
				createDB := fmt.Sprintf("CREATE DATABASE %s DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci", DB_Name)
				_, err = DBH.Exec(createDB)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to create database",
					})
					return
				}
				grantPrivilegesSQL := fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%' WITH GRANT OPTION", DB_Name, DB_Username)
				_, err = DBH.Exec(grantPrivilegesSQL)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to flush privileges",
					})
					return
				}
				_, err = DBH.Exec("INSERT INTO CastorDB.pollux_db (DB_UUID, DB_Name, DB_Username, DB_Password, DBH_UUID,Inst_UUID) VALUES (?, ?, ?, ?, ?, ?)", DB_UUID, DB_Name, DB_Username, DB_Password, dbManageParams.DBHUUID, dbManageParams.InstUUID)
				if err != nil {
					c.JSON(500, gin.H{
						"bool":    false,
						"message": "Failed to create database",
					})
					return
				}
				c.JSON(200, gin.H{
					"bool":    true,
					"message": "Successful to create database",
				})
				return
			} else {
				c.JSON(401, gin.H{
					"bool":    false,
					"message": "Not Allowed",
				})
				return
			}
		} else {
			c.JSON(401, gin.H{
				"bool":    false,
				"message": "Token verification failed",
			})
			return
		}
	})
	// 请求Pollux服务端 - 验证合法性
	auth.GET("/instWS", func(c *gin.Context) {
		wsHandler(c, db)
	})

	err = r.Run("0.0.0.0:521")
	if err != nil {
		return
	} // 监听并在 0.0.0.0:521 上启动服务
}

// 数据库连接
func dbConn() (*sql.DB, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")
	// 数据库连接字符串: "用户名:密码@tcp(主机:端口)/数据库名称?charset=utf8&parseTime=True&loc=Local"
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local",
		dbUser, dbPassword, dbHost, dbPort, dbName)
	// 打开数据库连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	// 确保连接可用
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully connected to the database!")
	return db, nil
}

func main() {
	fmt.Println("  ____          _             \n / ___|__ _ ___| |_ ___  _ __ \n| |   / _` / __| __/ _ \\| '__|\n| |__| (_| \\__ \\ || (_) | |   \n \\____\\__,_|___/\\__\\___/|_|   ")
	db, err := dbConn()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("Error closing the database connection: %v", err)
		}
	}()
	tinyAPI(db)
}
