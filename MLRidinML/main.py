import logging.config

from setting.LoggerConf import MY_LOGGING_CONFIG

from machinelearning import predict

logging.config.dictConfig(MY_LOGGING_CONFIG)
logger = logging.getLogger(__name__)

def main():
    predict.predict()

if __name__ == "__main__":
    main()