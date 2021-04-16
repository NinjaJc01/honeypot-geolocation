package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

const (
	defaultFields = "city,country,countryCode,region,regionName,city,isp,org,as,mobile,proxy,hosting,query"
	ReqPerMin = 14
)

var Database *sql.DB

type LoginData struct {
	LoginID       int    `db:"LoginID"`
	Username      string `db:"Username"`
	Password      string `db:"Password"`
	RemoteIP      string `db:"RemoteIP"`
	RemoteVersion string `db:"RemoteVersion"`
	Timestamp     string `db:"Timestamp"`
}

type ApiRequest struct {
	Query  string `json:"query"`
	Fields string `json:"fields"`
}

type ApiResponse struct {
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Region      string `json:"region"`
	RegionName  string `json:"regionName"`
	Zip         string `json:"zip"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`
	Mobile      bool   `json:"mobile"`
	Proxy       bool   `json:"proxy"`
	Hosting     bool   `json:"hosting"`
	Query       string `json:"query"`
}

func main() {
	err := connectDB()
	if err != nil {
		log.Panicln(err)
	}
	loginRecords, err := getLoginDataFromDB()
	if err != nil {
		log.Panicln(err)
	}
	log.Println(len(loginRecords))
	//TODO make IP records unique
	ips := uniqLoginIPs(loginRecords)
	// prettyPrint, _ := json.Marshal(ips)
	// log.Println(string(prettyPrint))
	log.Println(len(ips))
	geolocData, err := getDataWithRateLimit(ips)
	if err != nil {
		log.Panicln(err)
	}
	err = storeGeolocationData(geolocData)
	if err != nil {
		log.Panicln(err)
	}
}

func uniqLoginIPs(loginRecords []LoginData) []string {
	var loginRecordMap = make(map[string]int)
	for _, record := range loginRecords {
		loginRecordMap[strings.Split(record.RemoteIP, ":")[0]] = 1
	}

	keys := make([]string, 0, len(loginRecordMap))
	for key, _ := range loginRecordMap {
		keys = append(keys, key)
	}
	return keys
}

func getDataWithRateLimit(ipSlice []string) ([]ApiResponse, error) {
	var responseData []ApiResponse
	loginRecordsAligned := make([]string, ((len(ipSlice)/100)+1)*100)
	copy(loginRecordsAligned, ipSlice)
	var chunks [][]string
	for i := 0; i < len(ipSlice); i += 100 {
		chunks = append(chunks, loginRecordsAligned[i:i+100])
	}
	// prettyPrint, _ := json.Marshal(chunks)
	// log.Println(string(prettyPrint))
	//TODO Rate limiting can be massively improved
	//If you go over the limit your requests will be throttled (HTTP 429) until your rate limit window is reset. If you constantly go over the limit your IP address will be banned for 1 hour.

	//The returned HTTP header X-Rl contains the number of requests remaining in the current rate limit window. X-Ttl contains the seconds until the limit is reset.
	//Your implementation should always check the value of the X-Rl header, and if its is 0 you must not send any more requests for the duration of X-Ttl in seconds.
	for index, chunk := range chunks {
		log.Println("Grabbing data for chunk: ", index)
		statusCode, err, retryAfter, data := getGeolocationData(chunk)
		if err != nil {
			log.Panicln(err)
		}
		if statusCode == http.StatusTooManyRequests {
			backoffTime, err := strconv.Atoi(retryAfter)
			if err != nil {
				log.Println("Couldn't get RetryAfter seconds, got: ", retryAfter, err.Error())
				log.Println("Waiting for a minute due to RetryAfter failing to parse")
				time.Sleep(time.Second * 60)
			} else {
				log.Printf("429, backing off for %vs\n", backoffTime)
				time.Sleep(time.Second * time.Duration(backoffTime))
			}
			statusCode, err, retryAfter, data = getGeolocationData(chunk)
			if err != nil {
				log.Panicln(err)
			}
			if data != nil {
				responseData = append(responseData, data...)
			}
			if (index+1) % ReqPerMin == 0 {
				log.Println("Waiting for 60s to avoid rate limit")
				time.Sleep(time.Second * 60)
			}
		} else {
			if data != nil {
				responseData = append(responseData, data...)
			}
			if (index+1) % ReqPerMin == 0 {
				log.Println("Waiting for 60s to avoid rate limit")
				time.Sleep(time.Second * 60)
			}
		}
	}
	return responseData, nil
}

func connectDB() (err error) {
	Database, err = sql.Open("sqlite3", "honeypot.db?cache=shared&mode=memory")
	if err != nil {
		log.Println(err.Error())
	}
	Database.SetMaxOpenConns(5)
	return
}

func getLoginDataFromDB() ([]LoginData, error) {
	rows, err := Database.Query("SELECT * FROM Login;")
	if err != nil {
		return nil, err
	}
	var loginDataSlice []LoginData
	sqlx.StructScan(rows, &loginDataSlice)
	if err != nil {
		return nil, err
	}
	err = rows.Close()
	return loginDataSlice, err
}

// getGeolocationData expects slices of login data, with a size of 100 items at most.
func getGeolocationData(ipSlice []string) (statusCode int, err error, retryAfter string, data []ApiResponse) {
	var apiRequestContent []ApiRequest
	for _, record := range ipSlice {
		if record != "" { //THis deals with the final "chunk" which ends in several empty strings
			apiRequestContent = append(apiRequestContent, ApiRequest{Query: record, Fields: defaultFields})
		}
	}
	log.Println("Prepared request data")
	//reader, writer := io.Pipe()
	buff, err := json.Marshal(apiRequestContent)
	//json.NewEncoder(writer).Encode(apiRequestContent)
	resp, err := http.Post("http://ip-api.com/batch", "application/json", bytes.NewBuffer(buff)) //reader)
	//writer.Close()
	log.Println("Sent request")
	if err != nil {
		//log.Println(err.Error())
		return -1, err, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, resp.Header.Get("Retry-After"), nil
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return -1, err, "", nil
	}
	return 200, nil, "", data
}

func storeGeolocationData(data []ApiResponse) (error) {
	for _, record := range data {
		_, err := Database.Exec("INSERT INTO Geolocation (RemoteIP, Country, CountryCode, Region, RegionName, Zip, ISP, ASN, Mobile, Proxy, Hosting) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
		record.Query, record.Country, record.CountryCode, record.Region, record.RegionName, record.Zip, record.ISP, record.AS, record.Mobile, record.Proxy, record.Hosting)
		if err != nil {
			return err
		}
	}
	return nil
}