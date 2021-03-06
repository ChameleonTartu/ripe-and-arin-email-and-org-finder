# RIPE and ARIN abuse contact email and organisation name finder

This script allows to find DNS IP from any URL (so called `NSLOOKUP`) and based on retrieved IP find abuse contact and organisation name in RIPE and ARIN databases.

NOTE: Please, take into account that if you need to use this script to do a lookup at RIPE DB, you will need to change string `investigation007` to some unique string that will be associated with your application.

## Format of the .xlsx file to run the script on

File should have, at least 3 columns:

```
Video URL, Abuse contact, Responsible Org
```

The 4th column will be created automatically if will not exist `DNS IP`

The file can have more columns, they will be written to the same file with no changes.


## Usage of the script

```[python]
python whois_and_abuse_contact_finder.py <filename.xlsx> <worksheet>
```

By default, `myworkbook.xlsx` is the name of the file and `INVESTIGATION` is the name of the `worksheet`.

## Recommendations

Based on my personal experience it is always better to create virtual environment to run different small scripts. Therefore, in the documentation I provide `requirements.txt` file with required dependencies. To install them you need to activate virtual environment and run `pip install -r requirements.txt`. The script was tested for `Python3.6` and should work for `Python3.6+`. If it is not the case, feel free to create an issue to this repository.
