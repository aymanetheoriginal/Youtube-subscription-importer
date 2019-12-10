import google_auth_oauthlib.flow
import googleapiclient.discovery
import googleapiclient.errors

from xml.dom import minidom
import urllib.parse

import os,sys
import requests

#print(sys.version[0])    #debug
scopes = ["https://www.googleapis.com/auth/youtube.force-ssl"]

def authO():
    # Disable OAuthlib's HTTPS verification when running locally.
    # *DO NOT* leave this option enabled in production.
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    api_service_name = "youtube"
    api_version = "v3"
    client_secrets_file = "client_secret.json"

    # Get credentials and create an API client
    flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(client_secrets_file, scopes)
    credentials = flow.run_console("Please visit this URL to authorize this application:\n\n{url}\n")
    #print("credentials after run console : {}".format(credentials.token))
    return credentials.token



def extract_channel_IDs(channels_list):
  subscription_file = str(input("subscription file (.xml) : "))
  if(not os.path.exists(subscription_file)):
    print("[-]Your subscription file not exists ...")
    os._exit(1)
  print("[+]Your subscription file is exists and imported successfully ...")
  xmldoc = minidom.parse(subscription_file)
  itemlist = xmldoc.getElementsByTagName('outline')[1:]
  for xml_url in itemlist:
    xml_url = xml_url.attributes['xmlUrl'].value
    parse = urllib.parse.urlparse(xml_url)
    channel_id = urllib.parse.parse_qs(parse.query)["channel_id"][0]          # !! Important
    channels_list.append(channel_id)
  return len(itemlist)

def user_index_save(counter):
    file = open("INEDX.log","w")
    file.write(str(counter))
    file.close()
    print("index number saved successfully in this file ./INDEX.log")
    os._exit(1)

channels_list = []
n_of_channels = extract_channel_IDs(channels_list)
print("number of channels : {0} \nwait to Extract ...".format(n_of_channels))

authToken = authO()
authToken = "Bearer {}".format(authToken)

user_index = str(input("[+]Your index (default : 0) : "))
if(not user_index.isdecimal() or len(user_index) == 0):
    user_index = 0

headers={
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0",
"Authorization": authToken,
"Content-Type": "application/json",
"Connection": "close"
}

counter = int(user_index)
while(counter < len(channels_list)):
  channel_id = channels_list[counter]
  json_data = {"snippet":{"resourceId":{"kind":"youtube#channel","channelId":channel_id}}}
  r = requests.post("https://content.googleapis.com/youtube/v3/subscriptions?part=snippet&alt=json",json=json_data,headers=headers)
  response_status_code = r.status_code
  if(response_status_code == 200):
      print("[{0}/{1}] :: {2} :: {3}".format(counter+1,n_of_channels,channel_id,"200:OK"))
      counter += 1
  elif(response_status_code == 400):
      print("Too many recent subscriptions.\nmore info : https://developers.google.com/youtube/v3/docs/errors")
      print("Try after a few hours Using this index number : {}".format(counter))
      user_index_save(counter)
  elif(response_status_code == 403):
      print("error... status code : {}".format(response_status_code))
      print("more details : https://developers.google.com/youtube/v3/docs/errors")
      user_index_save(counter)
  elif(response_status_code == 404):
      print("[{0}/{1}] :: {2} :: {3}".format(counter+1,n_of_channels,channel_id,"channelNotFound"))
      counter += 1
  else:
      print("Error response status code : {}\nmore info : https://developers.google.com/youtube/v3/docs/errors".format(response_status_code))
      user_index_save(counter)
