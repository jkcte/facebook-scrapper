# Basic
python facebookScrape.py `
  --link "https://www.facebook.com/groups/onepiyucommunity" `
  --har-export ".\network.har" `
  --scrolls 100


# With keyword filter
py runScript.py --link "https://www.facebook.com/profile/100069113923869/search/?q=heat%20index" --output heat_results.csv --filter "heat index"

# If your scraper names files like *graphQL*.har and you only want those:
py runScript.py --link "https://www.facebook.com/profile/100069113923869/search/?q=walang%20pasok" --output results.csv --only-graphql-name

# If the scraper saves HARs somewhere else:
py runScript.py --link "..." --output results.csv --har-dir "C:\Users\Owner\Documents\GitHub\facebook-scrapper\debug_graphql_cap"
