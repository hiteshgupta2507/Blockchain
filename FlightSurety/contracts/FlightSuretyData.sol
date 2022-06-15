pragma solidity ^0.4.25;

import "../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

contract FlightSuretyData {
    using SafeMath for uint256;

    /********************************************************************************************/
    /*                                       DATA VARIABLES                                     */
    /********************************************************************************************/

    address private contractOwner; // Account used to deploy contract
    bool private operational = true; // Blocks all state changes throughout the contract if false

    struct Airline {
        bool sIsRegistered;
        bool sIsFunded;
        uint256 sFunds;
    }

    struct InsuranceClaim {
        address sPassenger;
        uint256 sPuchaseAmount;
        uint256 sPayoutPercentage;
        bool sCredited;
    }

    // Flights
    struct Flight {
        bool sIsRegistered;
        bytes32 sFlightKey;
        address sAirline;
        string sFlightNumber;
        uint8 sStatusCode;
        uint256 sTimestamp;
        string sDepartureLocation;
        string sArrivalLocation;
    }

    mapping(address => Airline) private airlines;
    mapping(bytes32 => InsuranceClaim[]) public flightInsuranceClaims;
    mapping(bytes32 => Flight) public flights;
    mapping(address => uint256) public withdrawableFunds;

    bytes32[] public registeredFlights;
    uint256 registeredAirlineCount = 0;
    uint256 fundedAirlineCount = 0;

    /********************************************************************************************/
    /*                                       EVENT DEFINITIONS                                  */
    /********************************************************************************************/

    event AirlineRegistered(address airline);
    event PassengerInsured(
        bytes32 flightKey,
        address passenger,
        uint256 amount,
        uint256 payout
    );
    event InsureeCredited(bytes32 flightKey, address passenger, uint256 amount);
    event PayInsuree(address payoutAddress, uint256 amount);
    event AirlineFunded(address airline);

    /**
     * @dev Constructor
     *      The deploying account becomes contractOwner
     */
    constructor() public {
        contractOwner = msg.sender;
    }

    /********************************************************************************************/
    /*                                       FUNCTION MODIFIERS                                 */
    /********************************************************************************************/

    // Modifiers help avoid duplication of code. They are typically used to validate something
    // before a function is allowed to be executed.

    /**
     * @dev Modifier that requires the "operational" boolean variable to be "true"
     *      This is used on all state changing functions to pause the contract in
     *      the event there is an issue that needs to be fixed
     */
    modifier requireIsOperational() {
        require(operational, "Contract is currently not operational");
        _; // All modifiers require an "_" which indicates where the function body will be added
    }

    /**
     * @dev Modifier that requires the "ContractOwner" account to be the function caller
     */
    modifier requireContractOwner() {
        require(msg.sender == contractOwner, "Caller is not contract owner");
        _;
    }

    modifier requireIsFlightRegistered(bytes32 flightKey) {
        require(flights[flightKey].sIsRegistered, "Flight is not registered");
        _;
    }

    /********************************************************************************************/
    /*                                       UTILITY FUNCTIONS                                  */
    /********************************************************************************************/

    /**
     * @dev Get operating status of contract
     *
     * @return A bool that is the current operating status
     */
    function isOperational() public view returns (bool) {
        return operational;
    }

    /**
     * @dev Sets contract operations on/off
     *
     * When operational mode is disabled, all write transactions except for this one will fail
     */
    function setOperatingStatus(bool mode) external requireContractOwner {
        operational = mode;
    }

    /********************************************************************************************/
    /*                                     SMART CONTRACT FUNCTIONS                             */
    /********************************************************************************************/

    /**
     * @dev Add an airline to the registration queue
     *      Can only be called from FlightSuretyApp contract
     *
     */
    function registerAirline(address newAirline) external requireIsOperational {
        airlines[newAirline] = Airline(true, false, 0);
        registeredAirlineCount = registeredAirlineCount.add(1);
        emit AirlineRegistered(newAirline);
    }

    function isFlightRegistered(bytes32 flightKey) public view returns (bool) {
        return flights[flightKey].sIsRegistered;
    }

    function isFlightLanded(bytes32 flightKey) public view returns (bool) {
        if (flights[flightKey].sStatusCode > 0) {
            return true;
        }
        return false;
    }

    /**
     * @dev Buy insurance for a flight
     *
     */
    function buy(
        bytes32 flightKey,
        address passenger,
        uint256 amount,
        uint256 payout
    ) external payable requireIsOperational {
        require(isFlightRegistered(flightKey), "Flight is already registered");
        require(!isFlightLanded(flightKey), "Flight has already landed");

        flightInsuranceClaims[flightKey].push(
            InsuranceClaim(passenger, amount, payout, false)
        );
        emit PassengerInsured(flightKey, passenger, amount, payout);
    }

    /**
     *  @dev Credits payouts to insurees
     */
    function creditInsurees(bytes32 flightKey) external requireIsOperational {
        for (uint256 i = 0; i < flightInsuranceClaims[flightKey].length; i++) {
            InsuranceClaim memory insuranceClaim = flightInsuranceClaims[
                flightKey
            ][i];
            insuranceClaim.sCredited = true;
            uint256 amount = insuranceClaim
                .sPuchaseAmount
                .mul(insuranceClaim.sPayoutPercentage)
                .div(100);
            withdrawableFunds[insuranceClaim.sPassenger] = withdrawableFunds[
                insuranceClaim.sPassenger
            ].add(amount);
            emit InsureeCredited(flightKey, insuranceClaim.sPassenger, amount);
        }
    }

    /**
     *  @dev Transfers eligible payout funds to insuree
     *
     */
    function pay(address payoutAddress) external payable requireIsOperational {
        uint256 amount = withdrawableFunds[payoutAddress];
        require(
            address(this).balance >= amount,
            "Contract has insufficient funds."
        );
        require(amount > 0, "There are no funds available for withdrawal");
        withdrawableFunds[payoutAddress] = 0;
        address(uint160(address(payoutAddress))).transfer(amount);
        emit PayInsuree(payoutAddress, amount);
    }

    /**
     * @dev Initial funding for the insurance. Unless there are too many delayed flights
     *      resulting in insurance payouts, the contract should be self-sustaining
     *
     */
    function fund(address airline, uint256 amount)
        public
        payable
        requireIsOperational
    {
        airlines[airline].sIsFunded = true;
        airlines[airline].sFunds = airlines[airline].sFunds.add(amount);
        fundedAirlineCount = fundedAirlineCount.add(1);
        emit AirlineFunded(airline);
    }

    function getFlightKey(
        address airline,
        string memory flight,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(airline, flight, timestamp));
    }

    /**
     * @dev Fallback function for funding smart contract.
     *
     */
    function() external payable {
        // fund(address airline, uint256 amount);
    }
}
