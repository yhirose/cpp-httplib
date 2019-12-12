import os

border = '// ----------------------------------------------------------------------------'

with open('httplib.h') as f:
    lines = f.readlines()
    inImplementation = False
    os.makedirs('out', exist_ok=True)
    with open('out/httplib.h', 'w') as fh:
        with open('out/httplib.cc', 'w') as fc:
            fc.write('#include "httplib.h"\n')
            fc.write('namespace httplib {\n')
            for line in lines:
                isBorderLine = border in line
                if isBorderLine:
                    inImplementation = not inImplementation
                else:
                    if inImplementation:
                        fc.write(line.replace('inline ', ''))
                        pass
                    else:
                        fh.write(line)
                        pass
            fc.write('} // namespace httplib\n')
