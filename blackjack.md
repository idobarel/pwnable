# BLACKJACK
This one is super nice.

There is a lot of code, we just need to make sure we focus on the right thing.

The interesting part here is the `betting` function:
```c
int betting() //Asks user amount to bet
{
 printf("\n\nEnter Bet: $");
 scanf("%d", &bet);
 
 if (bet > cash) //If player tries to bet more money than player has
 {
        printf("\nYou cannot bet more money than you have.");
        printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
 }
 else return bet;
}
```
And this part:
```C
if(player_total<dealer_total) //If player's total is less than dealer's total, loss
      {
         printf("\nDealer Has the Better Hand. You Lose.\n");
         loss = loss+1;
         cash = cash - bet;
         printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
         dealer_total=0;
         askover();
      }
```
The is no check if the bet is negative.
So we can just place a `-100000000` bet, and loose a game.
```
Cash: $500
-------
|C    |
|  4  |
|    C|
-------

Your Total is 4

The Dealer Has a Total of 2

Enter Bet: $-1000000000


Would You Like to Hit or Stay?
Please Enter H to Hit or S to Stay.
s

You Have Chosen to Stay at 4. Wise Decision!

The Dealer Has a Total of 7
The Dealer Has a Total of 12
The Dealer Has a Total of 17
Dealer Has the Better Hand. You Lose.

You have 0 Wins and 1 Losses. Awesome!

Would You Like To Play Again?
Please Enter Y for Yes or N for No
Y

YaY_I_AM_A_MILLIONARE_LOL
```
