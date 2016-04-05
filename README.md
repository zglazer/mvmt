#The Movment - Manage Your Amazon S3 Websites
A simple Python package to easily create and manage your Amazon S3 static websites.

##Why?
Configuring a static website on Amazon S3 is pretty simple if you only plan
on having a single website. The Movement is meant to allow you or your team 
to very easily update and manage lots of websites on S3.

##Usage
``` 
    mvmt.py new DOMAIN [--region=REGION]
    mvmt.py push DOMAIN DIRECTORY [--region=REGION]
    mvmt.py clean DOMAIN [--region=REGION]
    mvmt.py del DOMAIN [--region=REGION]
    mvmt.py route DOMAIN [--region=REGION] [--comment=COMMENT]
    mvmt.py -h | --help

Arguments:
    DOMAIN             The root domain of your website. This will also be your
                       bucket name.

    DIRECTORY          The directory that will be pushed to S3.
                       Can be an absolute or relative path.
Options:
    -h --help          Show this screen.
    --region=REGION    Specify an AWS region. [default: us-east-1]
    --comment=COMMENT  Specify a comment for your new hosted zone.
                       [default: My New Website]
```