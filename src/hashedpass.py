import os
import json
import sys
import hashlib
import passlib
import passlib.hash

# Default argon2 properties as defined in the protocol specification.
DEFAULT_MEM_SIZE = 262144 # in KiB
DEFAULT_ITERATIONS = 24
DEFAULT_PARALLELISM = 2
DEFAULT_KEYLENGTH = 32
DEFAULT_SALT = b"1" * 8

class Argon2Parameters:
    "A class organizing Argon2 parameters"

    class MalformedParameter(Exception):
        pass

    def __init__(self, memory, iterations, threads, size, salt):
        self.memory = memory
        self.iterations = iterations
        self.threads = threads
        self.size = size
        self.salt = salt

    # Argon2 parameter string in the format of:
    # memory:iterations:timecost:size:salt

    @staticmethod
    def from_string(string: str):
        "Initialize an Argon2Parameters object using the Argon2 parameter string."

        # Convert each element to an integer.
        strtokens = string.split(":")
        tokens = [int(x) for x in strtokens[0 - 3]]
        
        # Detect if the parameter is incorrect
        if (len(tokens) < 5):
            raise Argon2Parameters.MalformedParameter("Argon2 parameter string is incorrect")

        return Argon2Parameters(tokens[0], tokens[1], tokens[2], tokens[3], strtokens[4])




class Constraints:
    "Represents constraints and applies them in a consistent fashion."

    CAPITALS = list("QWERTYUIOPASDFGHJKLZXCVBNM")

    class MalformedConstraint(Exception):
        pass

    def __init__(self, length = 0, ochars = [], achars = [], from_string: str = None):
        
        # This relates the abbreviations found in the constraint format to variables here.
        code_to_variable = {
            "l": (length, int),
            "oc": (ochars, list),
            "ac": (achars, list)
        }
        
        # If we are constructing this object from a String
        if (from_string != None):
            fields = from_string.split(";")
            for field in fields:
                key = field.split("=")[0]
                value = field.split("=")[1]

                # If the key is not recognized as a valid constraint (defined within the format)
                if (key not in code_to_variable.keys()):
                    raise Constraints.MalformedConstraint("Malformed constraint")

                # If dealing with a normal, scalar value.
                # Also, preform some type casting when necessary.
                if (not value.startswith("[")):
                    code_to_variable[key][0] = code_to_variable[key][1](value)
                    continue

                # Parse the array type and load in the array where it needs to go.
                value = value.lstrip("[").rstrip("]")
                values = value.split(",")
                code_to_variable[key] = values
                
        self.length = length
        self.ochars = ochars
        self.achars = achars


    def apply(self, seed: int, password: str):
        # Strings are immutable in Python, so let's make a list.
        result = list(password)

        # If there are length constraints, truncate the hash by it. 
        if (self.length != 0):
            result = result[0 : self.length - 1]

        # Position of where the number will go. 
        number_pos = seed % (len(result) - 1)
        if (number_pos == 0):
            number_pos = 1

        # Apply the random number clause between first char and second last character of digest.
        result[number_pos] = str(seed % 10)

        # Apply the random capital letter clause at the end of the Base64 digest.
        result[-1] = self.CAPITALS[seed % 26]

        # Keeps track of the index for AND characters.
        char_index = 1
        
        # The first character will be any of the OR required characters--if this is a constraint! 
        if (self.ochars != []):
            result[0] = self.ochars[seed % len(self.ochars)]

        # For every required character/symbol
        for achar in self.achars:
            # We do not want to overwrite the number 
            if (char_index == number_pos):
                char_index += 1

            # Set the required character after the first element (the OR required character)
            # then keep increasing the index after that
            result[char_index] = achar
            char_index += 1

        # Return the post-processed digest.
        return str("".join(result))


    def __str__(self):
        result = ""

        if (self.length != 0):
            result += f"l={self.length};"

        if (self.ochars != []):
            result += "oc=[" + ",".join(self.ochars) + "];"

        if (self.achars != []):
            result += "ac=[" + ",".join(self.achars) + "];"


        return result.rstrip(";")

        

            
class HashedPassword:
    "Represents the resulting hashed password, with its digest and its parameters."

    def __init__(self, digest, argon2_params, constraints):
        self.digest = digest
        self.argon2 = argon2_params
        self.constraints = constraints



class Password:
    "Represents a password that will be hashed to create a unique, secure one"

    def __init__(self, mpassword, service, id, constraints, 
                        iterations = DEFAULT_ITERATIONS,
                        memory = DEFAULT_MEM_SIZE,
                        threads = DEFAULT_PARALLELISM,
                        digestsize = DEFAULT_KEYLENGTH,
                        salt = DEFAULT_SALT):

        self.mpassword: str = mpassword
        self.service: str = service
        self.id: str = id
        self.constraints: Constraints = constraints

        self.iterations = iterations
        self.memory = memory
        self.threads = threads
        self.digestsize = digestsize
        self.salt = salt

    def hash(self) -> str:
        tbc = "{mpass}={service}={id}".format(
            mpass = self.mpassword,
            service = self.service.lower(),
            id = self.id.lower()
        )

        hashed = hashlib.sha512(tbc.encode()).digest()
        argon2i: passlib.hash.argon2 = passlib.hash.argon2.using(
            salt = self.salt,
            memory_cost = self.memory,
            digest_size = self.digestsize,
            max_threads = self.threads,
            time_cost = self.iterations
        )


        b64_hash = argon2i.hash(hashed).split("$")[-1]
        seed = ord(b64_hash[0])

        return self.constraints.apply(seed, b64_hash)


    def __str__(self):
        return self.hash()

