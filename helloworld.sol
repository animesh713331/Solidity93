// 1. We tell the compiler what license we're using. It's just a good habit.
// SPDX-License-Identifier: MIT

// 2. We tell the compiler which version of Solidity to use.
pragma solidity ^0.8.20;

// 3. We define our contract. Think of it like a 'class' in C++.
contract HelloWorld {
    // 4. This is a "State Variable". It is data stored permanently
    //    with the contract on the blockchain.
    string public greeting = "Hello, World!";
}
