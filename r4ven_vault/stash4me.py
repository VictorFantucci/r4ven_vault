"""
This module contains the class that works as a password vault.
"""
import os
import logging
from r4ven_utils.log4me import function_logger
from cryptography.fernet import Fernet

class PasswordManager:

    def __init__(self) -> None:
        """
        Basic constructor of the class PasswordManager
        """
        # By default no encryption key is defined.
        self.key = None
        # By default no password file is defined.
        self.password_file = None
        # Dictionary used to add passwords to the r4ven_vault.
        self.password_dict = {}

    def create_key(self, encryption_key_file_path: str) -> None:
            """
            Method that generates the encryption key and store it in a .key file.

            Args:
                encryption_key_path (str): The path to directory where the encryption
                key will be stored.
            """
            # Create a logger object for this function.
            create_key_logger = function_logger(console_level=logging.INFO)

            # Calls the the Fernet.generate_key() method to create the encryption key.
            self.key = Fernet.generate_key()
            create_key_logger.info("The encryption key was generated successfully.\n"
                                + "ENCRYPTION KEY: {}".format(self.key))

            # Create a file where the encryption key is going to be stored.
            try:
                with open (encryption_key_file_path, "wb") as file:
                    file.write(self.key)
                create_key_logger.info("The encryption key was stored in {}"
                                       .format(encryption_key_file_path))
            except FileNotFoundError:
                create_key_logger.error("No such file or directory: {}"
                                        .format(encryption_key_file_path))

    def load_key(self, encryption_key_file_path: str) -> None:
        """
        Method that loads the encryption key from the .key file.

        Args:
            encryption_key_path (str): The path to directory where the encryption key is stored.
        """
        # Creates a logger object for this function.
        load_key_logger = function_logger(console_level=logging.INFO)

        # Read the file where the encryption key is stored.
        try:
            with open (encryption_key_file_path, "rb") as file:
                self.key = file.read()
            load_key_logger.info("The encryption key was loaded from {}."
                                 .format(encryption_key_file_path))
        except FileNotFoundError:
            load_key_logger.error("No such file or directory: {}"
                                  .format(encryption_key_file_path))

    def create_password_file(self, passwords_file_path: str, initial_values: dict = None) -> None:
        """
        Method that initializes the password_file attribute.

        Args:
            passwords_file_path (str): The path to the directory where the file
            containing the passwords will be stored.
            initial_values (dict, optional): _description. Defaults to None.
        """
        # Creates a logger object for this function.
        create_password_file_logger = function_logger(console_level=logging.INFO)

        # Initialize the password file.
        try:
            self.password_file = passwords_file_path
            create_password_file_logger.\
                info(f"The password file was initialized in the {passwords_file_path} directory")
        except FileNotFoundError:
            create_password_file_logger.error("No such file or directory: {}"
                                              .format(passwords_file_path))

        # If there are initial values they will be written to the password file.
        if initial_values is not None:
            for key, value in initial_values.items():
                self.add_password(key, value)

    def load_password_file(self, password_file_path: str) -> None:
        """
        Method that loads the password_file.

        Args:
            password_file_path (str): The path to the directory where the file
            containing the passwords are stored.
        """
        # Creates a logger object for this function.
        load_password_file_logger = function_logger(console_level=logging.INFO)

        # Get the directory where the password file is stored.
        self.password_file = password_file_path

        # Decrypt each line of the password file.
        try:
            with open(password_file_path, "r") as file:
                for line in file:
                    # Pair of values, where 'app' is the app or website that has a password and
                    # the 'encrypted_password' is its access password, that need to be decrypted.

                    # Define the separator (":") that is used to split the password identifier and
                    # the password itself.
                    app, encrypted_password = line.split(":")
                    self.password_dict[app] = Fernet(self.key)\
                        .decrypt(encrypted_password.encode()).decode()
                load_password_file_logger.info("The password file was loaded from {}."
                                               .format(password_file_path))
        except FileNotFoundError:
            load_password_file_logger.error("No such file or directory: {}"
                                  .format(password_file_path))

    def add_password(self, app: str, password: str) -> None:
        """
        Method that adds a password to the password file.

        Args:
            app (str): The password identifier (key).
            password (str): The password itself.
        """
        # Create a logger object for this function.
        add_password_logger = function_logger(file_mode="a", console_level=logging.INFO)

        # Assign to the input password its own identifier (key).
        self.password_dict[app] = password

        # If the password file already exists, the new password will be appended to it.
        # Use append (a) instead of write (w) to not overwrite the file.
        if self.password_file is not None:
            with open(self.password_file, "a+") as file: # a+ -> append and read.
                # If there are multiple keys what's encrypted with one key MUST be decrypted
                # with the same key.

                # Encrypt the input password.
                encrypted_password = Fernet(self.key).encrypt(password.encode())
                file.write(app + ":" + encrypted_password.decode() + "\n")
                add_password_logger.info(f"The {app} password was encrypted and added to the "+\
                    "password file")

    def get_password(self, app: str) -> str:
        """
        Returns the password of the specified password identifier.

        Args:
            app (str): password identifier.

        Returns:
            str: The password itself.
        """
        # Create a logger object for this function.
        get_password_logger = function_logger(file_mode="a", console_level=logging.ERROR)

        try:
            get_password_logger.info("The {} password was consulted.".format(app))
            return self.password_dict[app]
        except KeyError:
            get_password_logger.error(f"No such key:{app} in the {self.password_file} directory.")

    def remove_password(self, app: str) -> None:
        """
        Removes the password of the specified password identifier.

        Args:
            app (str): Password identifier.
        """
        # Create a logger object for this function.
        remove_password_logger = function_logger(file_mode="a", console_level=logging.INFO)

        try:
            # Open the file in read mode and get all the lines from the file.
            with open(self.password_file, "r") as file:
                lines = file.readlines()
            # Reopen the file in write mode and write the lines back, except for the line that it's
            # going to be deleted.
            with open(self.password_file, "w") as file:
                for line in lines:
                    if line.strip("\n") != app:
                        file.write(line)
            remove_password_logger.info("The {} password has been removed.")
        except KeyError:
            remove_password_logger.error(f"No such key:{app} in the {self.password_file} directory.")
