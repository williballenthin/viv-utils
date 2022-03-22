from typing import List, Tuple, Optional

import vivisect
import vivisect.impemu.emulator
from typing_extensions import TypeAlias

Address: TypeAlias = int
DataType: TypeAlias = str
SymbolName: TypeAlias = str

CallingConvention: TypeAlias = str
ReturnType: TypeAlias = DataType
ReturnName: TypeAlias = str
FunctionName: TypeAlias = SymbolName
ArgType: TypeAlias = DataType
ArgName: TypeAlias = SymbolName
FunctionArg: TypeAlias = Tuple[ArgType, ArgName]
# type returned by `vw.getImpApi`
API: TypeAlias = Tuple[ReturnType, ReturnName, Optional[CallingConvention], FunctionName, List[FunctionArg]]
# shortcuts
Emulator: TypeAlias = vivisect.impemu.emulator.WorkspaceEmulator
Workspace: TypeAlias = vivisect.VivWorkspace
