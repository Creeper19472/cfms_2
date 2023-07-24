import sys
from jsonschema import validate, ValidationError

class StructureValidater():
    def checkGroupStructure(structure: dict):
        this_check_schema = {
            "type" : "object",
            "properties" : {
                "expire" : {"type" : "number"}
            },
        }

        if type(structure) != dict:
            return False
        
        for i in structure:
            try:
                validate(instance=structure[i], schema=this_check_schema)
            except ValidationError as e:
                return False, e
            
        return True
    
    checkRightStructure = checkGroupStructure # 目前它们的工作一样
        
if __name__ == "__main__":
    print(type({}) == dict)