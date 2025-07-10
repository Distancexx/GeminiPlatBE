package main

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type dockerContainerArgs struct {
	Game         string   `json:"Game"`
	Eula         string   `json:"eula"`
	SetupOnly    string   `json:"setupOnly"`
	ImageName    string   `json:"imageName"`
	InstanceName string   `json:"instanceName"`
	Port         []string `json:"port"`
	HostPath     string   `json:"hostPath"`
	MinMemory    string   `json:"minMemory"`
	MaxMemory    string   `json:"maxMemory"`
	CoreType     string   `json:"coreType"`
	CoreFile     string   `json:"coreFile"`
	CoreVersion  string   `json:"coreVersion"`
	Operate      string   `json:"operate"`
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
	//InstHostPath    string   `json:"inst_hostpath"`
	InstNowMem  string `json:"inst_nowmem"`
	InstMinMem  string `json:"inst_minmem"`
	InstMaxMem  string `json:"inst_maxmem"`
	InstNowDisk string `json:"inst_nowdisk"`
	InstMinDisk string `json:"inst_mindisk"`
	InstMaxDisk string `json:"inst_maxdisk"`
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

type nodeAddInfo struct {
	NodeIP        string `json:"node_ip"`
	NodePort      string `json:"node_port"`
	NodeAuthToken string `json:"node_AuthToken"`
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

type ContainerStats struct {
	CPUPercentage string `json:"cpu_percentage"`
	MemoryUsage   string `json:"memory_usage"`
	DiskUsage     string `json:"disk_usage"`
}

// dockerContainerCreateAndRun 创建并运行 Docker 容器
//func dockerContainerCreateAndRun(conn *websocket.Conn, args dockerContainerArgs) error {
//	if args.Game == "mc" && args.Eula == "TRUE" {
//		endArgs := "/bin/java -jar "
//		if args.CoreType != "CUSTOM" && args.CoreFile == "" {
//			subCmd := []string{"--name", args.InstanceName, "-d", "-p", args.Port + ":" + args.Port, "-v", args.HostPath + "/" + ":/data/", "-e", "UID=0", "-e", "GID=0", "-e", "CREATE_CONSOLE_IN_PIPE=TRUE", "-e", "EULA=" + args.Eula, "-e", "SETUP_ONLY=" + args.SetupOnly, "-e", "TYPE=" + args.CoreType, "-e", "VERSION=" + args.CoreVersion, "-e", "INIT_MEMORY=" + args.MinMemory, "-e", "MAX_MEMORY=" + args.MaxMemory, "--tty", "--interactive", args.ImageName}
//			err := cmdExecWithWS(conn, "docker", "run", subCmd...)
//			if err != nil {
//				return nil
//			}
//		} else if args.CoreType == "CUSTOM" && args.CoreFile != "" {
//			endArgs = endArgs + args.CoreFile
//			subCmd := []string{"--name", args.InstanceName, "-d", "-p", args.Port + ":" + args.Port, "-v", args.HostPath + "/" + ":/data/", "-e", "UID=0", "-e", "GID=0", "-e", "CREATE_CONSOLE_IN_PIPE=TRUE", "-e", "EULA=" + args.Eula, "-e", "SETUP_ONLY=" + args.SetupOnly, "-e", "TYPE=" + args.CoreType, "-e", "CUSTOM_SERVER=/data/" + args.CoreFile, "-e", "INIT_MEMORY=" + args.MinMemory, "-e", "MAX_MEMORY=" + args.MaxMemory, "--tty", "--interactive", args.ImageName}
//			err := cmdExecWithWS(conn, "docker", "run", subCmd...)
//			if err != nil {
//				return nil
//			}
//
//		}
//	} else {
//		err := cmdExecWithWS(conn, "echo", "!!!ERROR!!!")
//		if err != nil {
//			return nil
//		}
//	}
//	return nil
//}

// 命令执行
func cmdExec(mainCmd string, subCmd string, args ...string) bool {
	// 构建 docker exec 命令，使用参数化方式，防止命令注入
	cmd := exec.Command(mainCmd, append([]string{subCmd}, args...)...)
	//fmt.Println(cmd)
	// 设置标准输入、输出和错误输出
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	//执行命令
	if err := cmd.Run(); err != nil {
		fmt.Println("Error:", err)
		return false
	}
	return true
}

// 命令执行 + WS
func cmdExecWithWS(conn *websocket.Conn, mainCmd string, subCmd string, args ...string) error {
	// 构建 docker exec 命令，使用参数化方式，防止命令注入
	cmd := exec.Command(mainCmd, append([]string{subCmd}, args...)...)
	//fmt.Println(cmd)
	// 设置标准输入、输出和错误输出
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr
	// 获取标准输出和标准错误输出
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = fmt.Errorf("failed to get stdout pipe: %w", err)
		return err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = fmt.Errorf("failed to get stderr pipe: %w", err)
		return err
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		_ = fmt.Errorf("failed to run command: %w", err)
	}

	// 启动协程来处理标准输出
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			//fmt.Println("stdout: ", line)

			// 通过WebSocket发送到前端
			if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
				fmt.Println("WebSocket write error:", err)
				//break
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading stdout:", err)
		}
	}()

	// 启动协程来处理标准错误输出
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println("stderr: ", line)

			// 通过WebSocket发送到前端
			if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
				fmt.Println("WebSocket write error:", err)
				break
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading stderr:", err)
		}
	}()

	// 等待命令执行完毕
	//if err := cmd.Wait(); err != nil {
	//	_ = fmt.Errorf("command execution failed: %w", err)
	//}

	// 执行命令并返回可能的错误
	//return cmd.Run()
	return nil
	//return cmd.Wait()
}

// 获取系统资源信息
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

// 获取容器JSON信息
func getDockerContainerJSON(containerName string) types.ContainerJSON {
	// 创建Docker客户端
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
	}
	// 获取容器详细信息
	containerJSON, err := cli.ContainerInspect(context.Background(), containerName)
	if err != nil {
		log.Fatalf("Failed to inspect container: %v", err)
	}
	return containerJSON
}

func fetchDockerContainerStatsJSON(containerID string, instPath string) ContainerStats {
	//	创建Docker客户端
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
		return ContainerStats{}
	}
	//	获取容器详细信息
	stats, err := cli.ContainerStats(context.Background(), containerID, false)
	if err != nil {
		log.Fatalf("Failed to inspect container: %v", err)
		return ContainerStats{}
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("Failed to close body:", err)
		}
	}(stats.Body)
	//	读取容器状态信息
	var v *container.StatsResponse
	if err := json.NewDecoder(stats.Body).Decode(&v); err != nil {
		return ContainerStats{}
	}
	var containerStats ContainerStats
	//	计算CPU使用率
	if float64(v.CPUStats.SystemUsage) > 0 {
		containerStats.CPUPercentage = fmt.Sprintf("%.2f%%", (float64(v.CPUStats.CPUUsage.TotalUsage)/float64(v.CPUStats.SystemUsage))*100)
	} else {
		containerStats.CPUPercentage = "0%"
	}

	// 	计算内存使用量
	containerStats.MemoryUsage = fmt.Sprintf("%.2fGB", float64(v.MemoryStats.Usage)/(1024*1024*1024))
	// 	计算磁盘使用量
	cmd := exec.Command("du", "-sh", instPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Failed to get disk usage:", err)
		return ContainerStats{}
	}
	fields := strings.Fields(string(output))
	if len(fields) > 0 {
		containerStats.DiskUsage = fields[0] + "B"
	} else {
		containerStats.DiskUsage = "Error"
	}

	return containerStats
}

// 删除容器日志文件
func rmDockerContainerLogs(containerName string) {
	containerJSON := getDockerContainerJSON(containerName)
	// 提取并打印容器的Id值
	fmt.Printf("Container ID: %s\n", containerJSON.ID)
	dockerLogPath := "/var/lib/docker/containers/" + containerJSON.ID + "/" + containerJSON.ID + "-json.log"
	// 删除容器日志文件
	err := os.Remove(dockerLogPath)
	if err != nil {
		fmt.Println("Failed to remove container logs:", err)
	}
}

func getLinuxDistro() (string, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "", err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println("Failed to close file:", err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(line[3:], `"`), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "unknown", nil
}

// 递归函数，用于生成文件树
func getFileTree(rootPath string, currentPath string) ([]map[string]interface{}, error) {
	var result []map[string]interface{}
	absolutePath := filepath.Join(rootPath, currentPath)
	// 读取目录下的所有文件和文件夹
	files, err := os.ReadDir(absolutePath)
	if err != nil {
		return nil, err
	}

	// 遍历目录下的每一个文件和文件夹
	for _, file := range files {
		filePath := filepath.Join(currentPath, file.Name())
		if file.IsDir() {
			// 如果是目录，递归调用自身
			children, err := getFileTree(rootPath, filePath)
			if err != nil {
				return nil, err
			}
			result = append(result, map[string]interface{}{
				"name":     file.Name(),
				"path":     filePath,
				"type":     "dir",
				"children": children,
			})
		} else {
			// 如果是文件，直接添加到结果中
			result = append(result, map[string]interface{}{
				"name": file.Name(),
				"path": filePath,
				"type": "file",
			})
		}
	}
	return result, nil
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func wsHandler(c *gin.Context) {
	var InstanceName = c.Query("InstanceName")
	var Operate = c.Query("Operate")
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Println("Failed to set WebSocket upgrade:", err)
		//return
	}
	if Operate == "start" || Operate == "stop" || Operate == "restart" {
		go func() {
			// 操作容器
			err := cmdExecWithWS(conn, "docker", Operate, InstanceName)
			if err != nil {
				fmt.Println("Failed to start container:", err)
				err := conn.WriteMessage(websocket.TextMessage, []byte("Error: "+err.Error()))
				if err != nil {
					fmt.Println("Failed to send message:", err)
					return
				}
			}
			err = cmdExecWithWS(conn, "docker", "logs", "-f", InstanceName)
			if err != nil {
				fmt.Println("Failed to output container logs:", err)
				err := conn.WriteMessage(websocket.TextMessage, []byte("Error: "+err.Error()))
				if err != nil {
					fmt.Println("Failed to send message:", err)
					return
				}
			}
			// 发送成功信息
			err = conn.WriteMessage(websocket.TextMessage, []byte("Container operate and logs are being output"))
			if err != nil {
				fmt.Println("Failed to send message:", err)
				return
			}
		}()
		if Operate == "stop" {
			rmDockerContainerLogs(InstanceName)
		}
	} else if Operate == "logs" {
		go func() {
			err = cmdExecWithWS(conn, "docker", "logs", "-f", InstanceName)
			if err != nil {
				fmt.Println("Failed to output container logs:", err)
				err := conn.WriteMessage(websocket.TextMessage, []byte("Error: "+err.Error()))
				if err != nil {
					fmt.Println("Failed to send message:", err)
					//return
				}
			}
			// 发送成功信息
			err = conn.WriteMessage(websocket.TextMessage, []byte("Container operate and logs are being output"))
			if err != nil {
				fmt.Println("Failed to send message:", err)
			}
		}()
	}
	// 保持 WebSocket 连接打开，确保有足够时间执行命令和日志输出
	for {
		// WebSocket保持活跃状态，处理来自客户端的ping等操作
		_, responseC, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("WebSocket closed:", err)
			break
		}
		fmt.Println("Received message from client:", string(responseC))
		err = cmdExecWithWS(conn, "docker", "exec", InstanceName, "mc-send-to-console", string(responseC))
		if err != nil {
			fmt.Println("Failed to send message to container:", err)
			err := conn.WriteMessage(websocket.TextMessage, []byte("Error: "+err.Error()))
			if err != nil {
				fmt.Println("Failed to send message:", err)
				return
			}
		}
	}
	//defer func(conn *websocket.Conn) {
	//	err := conn.Close()
	//	if err != nil {
	//		fmt.Println("Failed to close WebSocket connection:", err)
	//	}
	//}(conn)
}

func main() {
	fmt.Println(" ____       _ _            \n|  _ \\ ___ | | |_   ___  __\n| |_) / _ \\| | | | | \\ \\/ /\n|  __/ (_) | | | |_| |>  < \n|_|   \\___/|_|_|\\__,_/_/\\_\\")

	var nodeAuthToken = "qweasdzxc"
	var currentVer = "v0.0.1"
	// 自动下载核心文件
	//var dockerArgs = dockerContainerArgs{"mc", "TRUE", "FALSE", "registry.cn-guangzhou.aliyuncs.com/ineko-docker/minecraft-server:latest", "mc", "25565", "/root/mctest", "1G", "1G", "PAPER", "", "1.20.2"}
	// 使用自定义核心文件
	//var dockerArgs = dockerContainerArgs{"mc", "TRUE", "FALSE", "registry.cn-guangzhou.aliyuncs.com/ineko-docker/minecraft-server:latest", "mc_custom", "25565-25570", "/root/mctest", "1G", "1G", "CUSTOM", "custom.jar", ""}
	// 创建并运行
	//cmdOutput := dockerContainerCreateAndRun(dockerArgs)
	// 仅运行
	//cmdOutput := dockerContainerStart("mc")
	// 日志输出
	//cmdOutput := dockerContainerLogsOut("mc")
	// 打印命令执行结果
	//cmdResPrint(cmdOutput)

	r := gin.Default()
	gin.ForceConsoleColor()
	// 配置CORS中间件
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},                   // 允许的来源
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},            // 允许的方法
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"}, // 允许的头
		ExposeHeaders:    []string{"Content-Length", "Download-File-Name", "Content-Disposition"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	// 实例交互websocket
	r.GET("/pollux/api/v1/instWS", wsHandler)
	// pollux节点绑定castor
	r.POST("/pollux/api/v1/bindToCastor", func(c *gin.Context) {
		var nodeInfo nodeAddInfo
		if err := c.ShouldBindJSON(&nodeInfo); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"bool": false, "error": err.Error()})
			return
		}
		if nodeInfo.NodeAuthToken == nodeAuthToken {
			//fmt.Println(nodeInfo)
			currentOS := runtime.GOOS
			if currentOS == "linux" {
				distro, err := getLinuxDistro()
				if err != nil {
					fmt.Println("Failed to get Linux distro:", err)
					c.JSON(500, gin.H{
						"bool":     false,
						"node_os":  "Failed to get OS",
						"node_ver": currentVer,
					})
				} else {
					fmt.Println("Linux distro:", distro)
					c.JSON(200, gin.H{
						"bool":     true,
						"node_os":  distro,
						"node_ver": currentVer,
					})
				}
			} else {
				fmt.Println(currentOS)
				c.JSON(200, gin.H{
					"bool":     true,
					"node_os":  currentOS,
					"node_ver": currentVer,
				})
			}
		} else {
			c.JSON(401, gin.H{"bool": false, "error": "Invalid AuthToken"})
			return
		}
	})
	// pollux节点获取系统信息
	r.POST("/pollux/api/v1/getSystemInfo", func(c *gin.Context) {
		systemInfo, err := getSystemInfo()
		if err != nil {
			c.JSON(500, gin.H{
				"bool":    false,
				"message": "服务器错误",
			})
		} else {
			c.JSON(200, gin.H{
				"bool":       true,
				"cpuLoad":    systemInfo.CpuLoad,
				"totalMem":   systemInfo.TotalMem,
				"freeMem":    systemInfo.FreeMem,
				"usedMem":    systemInfo.UsedMem,
				"totalDisk":  systemInfo.TotalDisk,
				"usedDisk":   systemInfo.UsedDisk,
				"freeDisk":   systemInfo.FreeDisk,
				"networkIn":  systemInfo.NetworkIn,
				"networkOut": systemInfo.NetworkOut,
			})
		}
	})
	// pollux节点健康检查
	r.POST("/pollux/api/v1/checkNodeHealth", func(c *gin.Context) {
		var jsonData nodeAddInfo
		if err := c.ShouldBindJSON(&jsonData); err != nil {
			c.JSON(400, gin.H{"bool": false, "error": err.Error()})
			return
		}
		//fmt.Println(jsonData.NodeAuthToken)
		if jsonData.NodeAuthToken == nodeAuthToken {
			c.JSON(200, gin.H{"bool": true})
		} else {
			c.JSON(401, gin.H{"bool": false, "error": "Invalid AuthToken"})
		}
	})
	// pollux 实例创建|删除
	r.POST("/pollux/api/v1/instAddDelEdit", func(c *gin.Context) {
		//	获取token并验证
		var jsonData instsListInfo
		if err := c.ShouldBindJSON(&jsonData); err != nil {
			c.JSON(400, gin.H{"bool": false, "error": err.Error()})
			return
		}
		if jsonData.Operate == "add" {
			if jsonData.InstGame == "minecraft" && jsonData.InstEula == "true" {
				if jsonData.CoreType != "CUSTOM" && jsonData.CoreFile == "" {
					// OS
					if runtime.GOOS == "linux" {
						args := []string{"--name", jsonData.InstName, "-d", "-v", "/var/GeminiPlatform/" + jsonData.InstUUID + ":/data", "-e", "UID=0", "-e", "GID=0", "-e", "CREATE_CONSOLE_IN_PIPE=TRUE", "-e", "EULA=" + jsonData.InstEula, "-e", "SETUP_ONLY=" + jsonData.InstSetupOnly, "-e", "TYPE=" + jsonData.CoreType, "-e", "VERSION=" + jsonData.CoreVersion, "-e", "INIT_MEMORY=" + jsonData.InstMinMem, "-e", "MAX_MEMORY=" + jsonData.InstMaxMem, "-e", "SERVER_PORT=" + jsonData.InstPorts[0], "--tty", "--interactive"}
						for _, port := range jsonData.InstPorts {
							args = append(args, "-p", port+":"+port)
						}
						args = append(args, "registry.cn-chengdu.aliyuncs.com/geminip/mc-server-docker:"+jsonData.InstImageName)
						res := cmdExec("docker", "run", args...)
						if res {
							c.JSON(200, gin.H{"bool": true, "message": "Instance created successfully"})
						} else {
							c.JSON(500, gin.H{"bool": false, "error": "Failed to create instance"})
						}
					} else {
						c.JSON(500, gin.H{"bool": false, "error": "Unsupported OS"})
					}
				}

			}
			//	...Other Games...
		}
	})
	// pollux 实例文件管理
	r.POST("/pollux/api/v1/instFiles", func(c *gin.Context) {
		//node_AuthToken := c.PostForm("node_AuthToken")
		type fileManagement struct {
			Node_AuthToken string   `json:"node_AuthToken"`
			Operation      string   `json:"operation"`
			InstPath       string   `json:"inst_path"`
			Name           string   `json:"name"`
			Content        string   `json:"content"`
			CheckedList    []string `json:"checked_list"`
		}
		var req fileManagement
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		if req.Node_AuthToken == nodeAuthToken {
			switch req.Operation {
			case "list":
				// 获取文件列表
				fileTree, err := getFileTree(req.InstPath, "")
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"files": fileTree})

			case "readFile":
				// 读取文件内容
				if req.Name == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "File name is required"})
					return
				}
				cleanName := filepath.Clean(req.Name)
				targetPath := filepath.Join(req.InstPath, cleanName)
				if !strings.HasPrefix(targetPath, filepath.Clean(req.InstPath)) {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file path"})
					return
				}
				content, err := os.ReadFile(targetPath)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"content": string(content)})

			case "writeFile":
				// 写入文件内容
				if req.Name == "" || req.Content == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "File name and content are required"})
					return
				}
				cleanName := filepath.Clean(req.Name)
				targetPath := filepath.Join(req.InstPath, cleanName)
				if !strings.HasPrefix(targetPath, filepath.Clean(req.InstPath)) {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file path"})
					return
				}
				req.Content = strings.ReplaceAll(req.Content, "\r\n", "\n")
				err := os.WriteFile(targetPath, []byte(req.Content), 0644)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "File saved successfully"})

			case "createFile":
				// 创建新文件
				if req.Name == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "File name is required"})
					return
				}
				cleanName := filepath.Clean(req.Name)
				targetPath := filepath.Join(req.InstPath, cleanName)
				if !strings.HasPrefix(targetPath, filepath.Clean(req.InstPath)) {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file path"})
					return
				}
				file, err := os.Create(targetPath)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				err = file.Close()
				if err != nil {
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "File created successfully"})

			case "createDir":
				// 创建新文件夹
				if req.Name == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Folder name is required"})
					return
				}
				cleanName := filepath.Clean(req.Name)
				targetPath := filepath.Join(req.InstPath, cleanName)
				if !strings.HasPrefix(targetPath, filepath.Clean(req.InstPath)) {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file path"})
					return
				}
				err := os.Mkdir(targetPath, 0755)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "Folder created successfully"})

			case "delete":
				// 删除目录 / 文件
				if req.CheckedList == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Folder name is required"})
					return
				}
				for _, checkedItem := range req.CheckedList {
					cleanName := filepath.Clean(checkedItem)
					targetPath := filepath.Join(req.InstPath, cleanName)
					if !strings.HasPrefix(targetPath, filepath.Clean(req.InstPath)) {
						c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file path"})
						return
					}
					if _, err := os.Stat(targetPath); os.IsNotExist(err) {
						//c.JSON(http.StatusBadRequest, gin.H{"error": "File not exist"})
						continue
					}
					err := os.RemoveAll(targetPath)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
						return
					}
				}
				c.JSON(http.StatusOK, gin.H{"message": "Folder deleted successfully"})

			default:
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid operation"})
			}
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid AuthToken"})
		}
	})
	// pollux 文件下载
	r.POST("/pollux/api/v1/instFileDownload", func(c *gin.Context) {
		type instFileDownloadType struct {
			Node_AuthToken string   `json:"Node_AuthToken"`
			InstPath       string   `json:"InstPath"`
			FilesName      []string `json:"FilesName"`
		}
		var req instFileDownloadType
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		if req.Node_AuthToken == nodeAuthToken {
			if req.InstPath == "" || req.FilesName == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "File path and name are required"})
				return
			}
			if len(req.FilesName) == 1 {
				cleanName := filepath.Clean(req.FilesName[0])
				targetPath := filepath.Join(req.InstPath, cleanName)
				if !strings.HasPrefix(targetPath, filepath.Clean(req.InstPath)) {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file path"})
					return
				}
				c.Header("Content-Disposition", "attachment; filename="+cleanName)
				c.Header("Content-Type", "application/octet-stream")
				c.Header("Download-File-Name", cleanName)
				c.File(targetPath)
			} else {
				fmt.Println(req.FilesName)
				// 创建临时文件用于保存压缩包
				zipFile, err := os.CreateTemp("", "GPDownloadFiles_*.zip")
				if err != nil {
					c.JSON(500, gin.H{"error": "Failed to create zip file"})
					return
				}

				// 创建 zip.Writer 用于写入 zip 文件
				zipWriter := zip.NewWriter(zipFile)

				// 循环处理每个文件
				for _, fileName := range req.FilesName {
					cleanName := filepath.Clean(fileName)
					targetPath := filepath.Join(req.InstPath, cleanName)
					if !strings.HasPrefix(targetPath, filepath.Clean(req.InstPath)) {
						c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file path"})
						return
					}
					file, err := os.Open(targetPath)
					if err != nil {
						c.JSON(404, gin.H{"error": fmt.Sprintf("File %s not found", fileName)})
						return
					}
					defer func(file *os.File) {
						err := file.Close()
						if err != nil {
							fmt.Println("Failed to close file:", err)
							return
						}
					}(file)

					// 创建一个文件项并写入 zip 文件
					zipFileWriter, err := zipWriter.Create(fileName)
					if err != nil {
						c.JSON(500, gin.H{"error": "Failed to create zip entry"})
						return
					}

					// 将文件内容写入 zip 文件
					_, err = io.Copy(zipFileWriter, file)
					if err != nil {
						c.JSON(500, gin.H{"error": "Failed to write file to zip"})
						return
					}
				}

				// 关闭 zip.Writer
				err = zipWriter.Close()
				if err != nil {
					c.JSON(500, gin.H{"error": "Failed to close zip writer"})
					return
				}

				defer func() {
					// 删除临时文件
					err = os.Remove(zipFile.Name())
					if err != nil {
						fmt.Println("Failed to remove temp file:", err)
					}
				}()

				// 返回文件给前端
				c.Header("Content-Disposition", "attachment; filename="+filepath.Base(zipFile.Name()))
				c.Header("Download-File-Name", filepath.Base(zipFile.Name()))
				c.Header("Content-Type", "application/octet-stream")
				c.File(zipFile.Name())
			}
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid AuthToken"})
		}
	})
	// pollux 文件上传
	r.POST("/pollux/api/v1/instFileUpload", func(c *gin.Context) {
		node_AuthToken := c.PostForm("Node_AuthToken")
		instPath := c.PostForm("InstPath")
		file, _ := c.FormFile("uploadFile")
		if file == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
			return
		}
		if node_AuthToken == nodeAuthToken {
			// 保存文件到指定目录
			err := c.SaveUploadedFile(file, filepath.Join(instPath, file.Filename))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid AuthToken"})
		}
	})
	// pollux 获取实例占用内存和硬盘
	r.POST("/pollux/api/v1/instStats", func(c *gin.Context) {
		type instInfoType struct {
			Node_AuthToken string `json:"Node_AuthToken"`
			InstName       string `json:"InstName"`
			InstPath       string `json:"InstPath"`
		}
		var req instInfoType
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		if req.Node_AuthToken == nodeAuthToken {
			containerID := getDockerContainerJSON(req.InstName).ID
			containerStats := fetchDockerContainerStatsJSON(containerID, req.InstPath)
			c.JSON(200, gin.H{
				"containerStats": containerStats,
			})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid AuthToken"})
			return
		}
	})
	//启动服务
	err := r.Run("0.0.0.0:621")
	if err != nil {
		return
	}
}
