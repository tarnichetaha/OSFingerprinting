import models
import dbutils


if __name__ == "__main__":
    devices = dbutils.get_all_devices()
    for device in devices:
        devicemodel = models.Device(*device)
        print("="*50)
        print(devicemodel)