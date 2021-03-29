
function addListRange(list, start, end) {
  let index = start;
  while (index <= end) {
    list.push(index);
    index += 1;
  }
}


function dumpScriptType(list) {
  for (const target of list) {
    const hex = target.toString(16)
    console.log(`  kOpSuccess${target} = 0x${hex},` +
        `      //!< kOpSuccess${target} (BIP-342)`);
  }
}

function dumpScriptOperatorDefine(list) {
  for (const target of list) {
    console.log(`static const ScriptOperator ` +
        `OP_SUCCESS${target};   //!< OP_SUCCESS${target} (BIP-342)`);
  }
}

function dumpScriptOperatorImpl(list) {
  for (const target of list) {
    console.log(`const ScriptOperator ScriptOperator::` +
        `OP_SUCCESS${target}(kOpSuccess${target}, "OP_SUCCESS${target}");`);
  }
}

const main = function() {
  const targetList = [80, 98];
  addListRange(targetList, 126, 129);
  addListRange(targetList, 131, 134);
  addListRange(targetList, 137, 138);
  addListRange(targetList, 141, 142);
  addListRange(targetList, 149, 153);
  addListRange(targetList, 187, 254);

  dumpScriptType(targetList);
  dumpScriptOperatorDefine(targetList);
  dumpScriptOperatorImpl(targetList);
};

main();
