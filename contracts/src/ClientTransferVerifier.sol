// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 4468632331604761110831825473869606452275014241733654986294594325542139358097;
    uint256 constant deltax2 = 10516576287971042235031511388473867301391476686411223287142863928078454708840;
    uint256 constant deltay1 = 6487649980014844537830394332745178716752453940577994482452630673291927961717;
    uint256 constant deltay2 = 13342462584783966195619084710964950540149399167225789307209515881238140581864;

    
    uint256 constant IC0x = 1824678473629250120934916005622699722724793623784743615182069031917868882494;
    uint256 constant IC0y = 9490563754397006848707834125674303705881977132194222982641090282083826113878;
    
    uint256 constant IC1x = 12604409653971397176489610034186991074079401839410600111696666183496556175273;
    uint256 constant IC1y = 8077955768542737348377054477089128563801687283362643494612791710250389996893;
    
    uint256 constant IC2x = 3069618982701289359110228753358978374975622513407292590918439649504335764577;
    uint256 constant IC2y = 7010047773775784409489616669553460432429491712322576296358872983614204484172;
    
    uint256 constant IC3x = 15711135360352367207566649942466268222126910567603218538349606238738285077545;
    uint256 constant IC3y = 14983515598710068924827065436421975232309227221282259009906439747045042662684;
    
    uint256 constant IC4x = 4140724589918112218355285240096803784941651787888869589684091465101531004040;
    uint256 constant IC4y = 19237353800591041061216297225248827658329312494272791845433139714575344931811;
    
    uint256 constant IC5x = 17037106690679782458506717834467892489178829144575642647738502113743730597682;
    uint256 constant IC5y = 5786001905700972130927248042431839240827264020102571169148262297795758106152;
    
    uint256 constant IC6x = 20583874349605635705208408282223602332110583781833991878158494640398287953523;
    uint256 constant IC6y = 17464240717171832354786100023675284369729008997730395051930434038019683830825;
    
    uint256 constant IC7x = 4694370779655391459883686306290153808126902812519525381847386440573902407248;
    uint256 constant IC7y = 8508181628383522686883464318310920312106144128103381753523055281732328121557;
    
    uint256 constant IC8x = 3898025131085499733585217680409806170241592160658406988353377639370578444310;
    uint256 constant IC8y = 6685967622293736940468153126341610141107994882802238782680995147497928190827;
    
    uint256 constant IC9x = 11002051701578046566773589414480412266905290126344964867494281310922510748908;
    uint256 constant IC9y = 3835772343193980525815580950279007460657232959302668025610204455201772081525;
    
    uint256 constant IC10x = 14460188182639001211746965148520828810415082210700574024796984382303424675561;
    uint256 constant IC10y = 15175459607087310035707214415086042890191173009215498423254192810820209219934;
    
    uint256 constant IC11x = 17440049162765574521462761733161493894114532937986518381803829931321238323753;
    uint256 constant IC11y = 3497439913696594986195042404744457617972370706833347500697333166404064934720;
    
    uint256 constant IC12x = 665507472413219682872834309201139686737922071379073128570901204690405765736;
    uint256 constant IC12y = 3995344100372190983342101280147320626823722040764736870755832939796282992694;
    
    uint256 constant IC13x = 423640307507743154865486673008255229604170019235933510960658294936565754130;
    uint256 constant IC13y = 21314795849564238274341472555913555704172687163495611811183376626114054463146;
    
    uint256 constant IC14x = 12740800817146433719893889218448570118684379832861346628782069645626052443909;
    uint256 constant IC14y = 13633771206548599530465891414340321834199943845724338171906971448739762462720;
    
    uint256 constant IC15x = 11485134467703515415438404195665523528923860938559174950314707404346199207270;
    uint256 constant IC15y = 12032995672429090905681801166869197367546197103311822764393128523451788022206;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[15] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
