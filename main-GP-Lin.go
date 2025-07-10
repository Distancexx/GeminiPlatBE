// 主安装
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// 命令执行
func commandExec(cmd string, args ...string) error {
	//ctx, cancel := context.WithCancel(context.Background())
	ctx, _ := context.WithCancel(context.Background())
	//go func(cancelFunc context.CancelFunc) {
	//time.Sleep(30 * time.Second)
	//cancelFunc()
	//}(cancel)

	c := exec.Command(cmd, args...)
	stdout, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		reader := bufio.NewReader(stdout)
		for {
			select {
			// 检测到ctx.Done()之后停止读取
			case <-ctx.Done():
				if ctx.Err() != nil {
					fmt.Printf("程序出现错误: %q", ctx.Err())
				} else {
					fmt.Println("程序被终止")
				}
				return
			default:
				readString, err := reader.ReadString('\n')
				if err != nil || err == io.EOF {
					return
				}
				fmt.Print(readString)
			}
		}
	}(&wg)
	err = c.Start()
	wg.Wait()
	return err
}

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

// 系统环境检测
func sysEnvCheck() {
	output, err := exec.Command("cat", "/etc/os-release").Output()
	//commandExec("cat", "/etc/os-release")
	if err != nil {
		fmt.Println("命令执行错误", err)
	}
	containsKeyword := strings.Contains(string(output), "Ubuntu")
	if containsKeyword {
		fmt.Println("当前系统为: Ubuntu")
	} else {
		fmt.Println("其他")
	}
}

// Docker环境检测
func dockerEnvCheck(optChoose int) bool {
	output, err := exec.Command("docker", "-v").Output()
	if err != nil {
		fmt.Println("Docker未安装，即将进行安装")
		err = commandExec("apt-get", "update")
		if err != nil {
			return false
		}
		err = commandExec("apt-get", "install", "ca-certificates", "curl", "-y")
		if err != nil {
			return false
		}
		err = commandExec("install", "-m", "0755", "-d", "/etc/apt/keyrings")
		if err != nil {
			return false
		}
		err = commandExec("curl", "-fsSL", "https://download.docker.com/linux/ubuntu/gpg", "-o", "/etc/apt/keyrings/docker.asc")
		if err != nil {
			return false
		}
		err = commandExec("chmod", "a+r", "/etc/apt/keyrings/docker.asc")
		if err != nil {
			return false
		}
		err = commandExec("sh", "-c", "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable\" | tee /etc/apt/sources.list.d/docker.list > /dev/null")
		if err != nil {
			return false
		}
		err = commandExec("apt-get", "update")
		if err != nil {
			return false
		}
		err = commandExec("apt-get", "install", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin", "-y")
		if err != nil {
			return false
		}
		fmt.Println("Docker安装完成")
		fmt.Println(" ")
		if optChoose == 2 {
			fmt.Println("正在配置Docker网桥")
			fmt.Println(" ")
			err = commandExec("docker", "network", "create", "--driver", "bridge", "--subnet", "172.20.0.0/16", "--gateway", "172.20.0.1", "pollux-br")
			if err != nil {
				return false
			}
			fmt.Println("Docker网桥配置完成")
			fmt.Println(" ")
			return true
		}
		return true
	} else {
		fmt.Println("Docker已安装, 版本为: " + string(output))
		return true
	}
}

// 密码创建以及对比
func pwdCheck(pwd string, checkedPwd string) bool {
	if pwd != checkedPwd {
		return false
	} else {
		return true
	}
}

// DBInstall 数据库容器安装
// typeOfDB: Castor / Pollux
func DBInstall(typeOfDB string) bool {
	fmt.Println("开始为" + typeOfDB + "安装MariaDB")
	//commandExec("docker", "pull", "mariadb")
	// 创建数据库ROOT密码
	fmt.Println("请为数据库创建ROOT密码: ")
	fmt.Println(" ")
	var DBRootPassword, checkedDBRootPassword string
	_, err := fmt.Scan(&DBRootPassword)
	if err != nil {
		return false
	}
	fmt.Println("再次确认数据库创建ROOT密码: ")
	fmt.Println(" ")
	_, err = fmt.Scan(&checkedDBRootPassword)
	if err != nil {
		return false
	}
	// 判断ROOT密码是否一致
	var checkedRootRes = pwdCheck(DBRootPassword, checkedDBRootPassword)
	if checkedRootRes {
		//	创建数据库Castor / Pollux数据库以及用户
		fmt.Println("请为数据库" + typeOfDB + "用户创建密码: ")
		fmt.Println(" ")
		var DBPassword, checkedDBPassword string
		_, err := fmt.Scan(&DBPassword)
		if err != nil {
			return false
		}
		fmt.Println("再次确认数据库" + typeOfDB + "用户创建密码: ")
		fmt.Println(" ")
		_, err = fmt.Scan(&checkedDBPassword)
		if err != nil {
			return false
		}
		// 判断Castor密码是否一致
		var checkedCastorRes = pwdCheck(DBPassword, checkedDBPassword)
		if checkedCastorRes {
			fmt.Println("数据库用户" + typeOfDB + "创建成功")
			fmt.Println(" ")
			fmt.Println("启动" + typeOfDB + "数据库")
			fmt.Println(" ")
			if typeOfDB == "Castor" {
				err = commandExec("cp", "./Castor/docker-compose.yml.bak", "./Castor/docker-compose.yml")
				if err != nil {
					return false
				}
				// 修改且调用docker-compose.yml
				err = commandExec("sh", "-c", "sed -i 's/MARIADB_ROOT_PASSWORD: geminiplat/MARIADB_ROOT_PASSWORD: "+DBRootPassword+"/g' ./Castor/docker-compose.yml")
				if err != nil {
					return false
				}
				err = commandExec("sh", "-c", "sed -i 's/MARIADB_PASSWORD: geminiplat/MARIADB_PASSWORD: "+DBPassword+"/g' ./Castor/docker-compose.yml")
				if err != nil {
					return false
				}
				err = commandExec("docker", "compose", "-f", "./Castor/docker-compose.yml", "up", "-d")
				if err != nil {
					return false
				}
				fmt.Println(" ")
				fmt.Println(typeOfDB + "数据库初始化完成并已启动")
				err = commandExec("rm", "./Castor/docker-compose.yml")
				if err != nil {
					return false
				}
				err = commandExec("cp", ".env.bak", ".env")
				if err != nil {
					return false
				}
				err = commandExec("sh", "-c", "sed -i 's/DB_PASSWORD = Castor/DB_PASSWORD = "+DBPassword+"/g' ./.env")
				if err != nil {
					return false
				}
				return true
				//	Developing
			} else if typeOfDB == "Pollux" {
				//commandExec("docker", "exec", "-i", "mariadb-Gemini-"+typeOfDB, "mysql", "-uCastor", "-p"+DBPassword, "-p", "source /var/gpsqlinit/pollux_ddl.sql")
				return false
			}
			//return true
		} else {
			fmt.Println("两次密码输入不一致，请重新输入")
			DBInstall(typeOfDB)
		}
	} else {
		fmt.Println("两次密码输入不一致，请重新输入")
		DBInstall(typeOfDB)
	}
	return false
}

func main() {
	fmt.Println("")
	fmt.Println("  ____                _       _ ____  _       _    __                      \n / ___| ___ _ __ ___ (_)_ __ (_)  _ \\| | __ _| |_ / _| ___  _ __ _ __ ___  \n| |  _ / _ \\ '_ ` _ \\| | '_ \\| | |_) | |/ _` | __| |_ / _ \\| '__| '_ ` _ \\ \n| |_| |  __/ | | | | | | | | | |  __/| | (_| | |_|  _| (_) | |  | | | | | |\n \\____|\\___|_| |_| |_|_|_| |_|_|_|   |_|\\__,_|\\__|_|  \\___/|_|  |_| |_| |_|")
	fmt.Println(" ")
	fmt.Println("感谢使用GeminiPlat Installer")
	fmt.Println(" ")
	var optChoose int
	//scan = fmt.Scan(&optConfirm)
	fmt.Println("请选择部署内容：")
	fmt.Println(" ")
	fmt.Println("1. GeminiPlat-前端Web面板")
	fmt.Println("2. GeminiPlat-后端Docker节点 (Developing)")
	_, err := fmt.Scan(&optChoose)
	if err != nil {
		return
	}
	if optChoose == 1 {
		sysEnvCheck()
		if dockerEnvCheck(optChoose) {
			fmt.Println("进入下一步")
			if DBInstall("Castor") {
				fmt.Println("Castor数据库安装成功")
			} else {
				fmt.Println("Castor数据库安装失败")
			}
		}
	} else if optChoose == 2 {
		sysEnvCheck()
		if dockerEnvCheck(optChoose) {
			fmt.Println("进入下一步")
			if DBInstall("Pollux") {
				fmt.Println("Pollux数据库安装成功")
			} else {
				fmt.Println("Pollux数据库安装失败")
			}
		}
	} else {
		fmt.Println("输入有误，重新执行")
		main()
	}
}
